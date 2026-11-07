using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.Core.Tests
{
    // Hermetic checks for the Windows engine service boundary foundation.
    // They create no pipe, process, service, route, or endpoint. The channel
    // is a fake. A pass here is not a Windows host result.
    internal static class ServiceBoundaryTests
    {
        private const string UserSid =
            "S-1-5-21-1111111111-2222222222-3333333333-1001";

        public static void Run(TestRunner runner)
        {
            runner.Check("service frame: a request round trips with a big-endian length", delegate
            {
                Dictionary<string, string> fields = RequestFields(
                    EngineProtocol.Operations.Status,
                    Session);

                byte[] frame;
                string code;
                AssertEx.True(EngineServiceFrame.TryEncode(fields, out frame, out code), "encode: " + code);
                AssertEx.Equal(4, EngineServiceFrame.LengthPrefixBytes, "prefix length");
                int prefix = ((frame[0] & 0xFF) << 24)
                    | ((frame[1] & 0xFF) << 16)
                    | ((frame[2] & 0xFF) << 8)
                    | (frame[3] & 0xFF);
                AssertEx.Equal(frame.Length - 4, prefix, "frame length after the prefix");

                Dictionary<string, string> decoded;
                AssertEx.True(
                    EngineServiceFrame.TryDecode(frame, frame.Length, out decoded, out code),
                    "decode: " + code);
                AssertEx.Equal("1", decoded[EngineProtocol.Keys.Version], "version");
                AssertEx.Equal("status", decoded[EngineProtocol.Keys.Operation], "operation");
                AssertEx.Equal(Session, decoded[EngineProtocol.Keys.Session], "session");

                int length;
                byte[] prefixOnly = new byte[] { frame[0], frame[1], frame[2], frame[3] };
                AssertEx.True(EngineServiceFrame.TryReadLength(prefixOnly, out length), "length read");
                AssertEx.Equal(frame.Length - 4, length, "length value");
            });

            runner.Check("service frame: a nested fields object is flattened", delegate
            {
                byte[] frame = RawFrame(
                    "{\"v\":\"1\",\"ok\":\"1\",\"fields\":{\"instance\":\"service-0001\"}}");
                Dictionary<string, string> fields;
                string code;
                AssertEx.True(
                    EngineServiceFrame.TryDecode(frame, frame.Length, out fields, out code),
                    "decode: " + code);
                AssertEx.Equal("service-0001", fields["instance"], "nested value");
                AssertEx.Equal("1", fields["ok"], "outer value");
            });

            runner.Check("service frame: scalar booleans and null become wire values", delegate
            {
                byte[] frame = RawFrame("{\"v\":\"1\",\"ok\":true,\"checked_at\":null}");
                Dictionary<string, string> fields;
                string code;
                AssertEx.True(
                    EngineServiceFrame.TryDecode(frame, frame.Length, out fields, out code),
                    "decode: " + code);
                AssertEx.Equal("1", fields["ok"], "true");
                AssertEx.Equal("", fields["checked_at"], "null");
            });

            runner.Check("service frame: a duplicate key is refused", delegate
            {
                AssertFrameRefused("{\"v\":\"1\",\"v\":\"2\"}", "duplicate");
            });

            runner.Check("service frame: an array, a fraction, and a leading zero are refused", delegate
            {
                AssertFrameRefused("{\"v\":[1]}", "array");
                AssertFrameRefused("{\"v\":1.5}", "fraction");
                AssertFrameRefused("{\"v\":01}", "leading zero");
            });

            runner.Check("service frame: a nested object other than fields is refused", delegate
            {
                AssertFrameRefused("{\"v\":{\"x\":\"1\"}}", "nested value");
                AssertFrameRefused("{\"v\":\"1\",\"fields\":{\"x\":{\"y\":\"1\"}}}", "deeper object");
            });

            runner.Check("service frame: a zero length, an oversized length, and trailing bytes are refused", delegate
            {
                byte[] zero = new byte[] { 0, 0, 0, 0 };
                Dictionary<string, string> fields;
                string code;
                AssertEx.False(EngineServiceFrame.TryDecode(zero, zero.Length, out fields, out code), "zero");
                int length;
                byte[] huge = new byte[] { 0, 1, 0, 1 };
                AssertEx.False(EngineServiceFrame.TryReadLength(huge, out length), "oversized prefix");

                byte[] frame;
                AssertEx.True(
                    EngineServiceFrame.TryEncode(
                        RequestFields(EngineProtocol.Operations.Hello, Session),
                        out frame,
                        out code),
                    "encode");
                AssertEx.False(EngineServiceFrame.TryDecode(frame, frame.Length - 1, out fields, out code), "short");
                AssertEx.False(EngineServiceFrame.TryDecode(frame, frame.Length - 2, out fields, out code), "shorter");
                AssertEx.False(EngineServiceFrame.TryDecode(frame, frame.Length + 1, out fields, out code), "count beyond the buffer");
            });

            runner.Check("service frame: a credential field is refused in both directions", delegate
            {
                Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
                fields["v"] = "1";
                fields["source_device_token"] = "abcd";
                byte[] frame;
                string code;
                AssertEx.False(EngineServiceFrame.TryEncode(fields, out frame, out code), "encode");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Forbidden, code, "encode code");

                byte[] inbound = RawFrame("{\"v\":\"1\",\"source_device_token\":\"abcd\"}");
                Dictionary<string, string> decoded;
                AssertEx.False(
                    EngineServiceFrame.TryDecode(inbound, inbound.Length, out decoded, out code),
                    "decode");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Forbidden, code, "decode code");
            });

            runner.Check("service frame: invalid UTF-8 is refused", delegate
            {
                byte[] payload = new byte[] { 0xC3, 0x28 };
                byte[] frame = new byte[6];
                frame[0] = 0;
                frame[1] = 0;
                frame[2] = 0;
                frame[3] = 2;
                frame[4] = payload[0];
                frame[5] = payload[1];
                Dictionary<string, string> fields;
                string code;
                AssertEx.False(EngineServiceFrame.TryDecode(frame, frame.Length, out fields, out code), "invalid UTF-8");
            });

            runner.Check("service boundary: the client mask is exact and has no create-instance right", delegate
            {
                AssertEx.Equal(0x00120183U, EngineServiceBoundary.PipeClientAccess, "client mask");
                AssertEx.Equal(0U, EngineServiceBoundary.PipeClientAccess & 0x00000004U, "no create-instance");
                uint mapped = EngineServiceBoundary.MapGenericToPipeAccess(EngineServiceBoundary.GenericWrite);
                AssertEx.Equal(0x00120116U, mapped, "generic write mapping");
                AssertEx.True((mapped & 0x00000004U) != 0, "generic write asks for create-instance");
                AssertEx.Equal(0x00120089U, EngineServiceBoundary.MapGenericToPipeAccess(EngineServiceBoundary.GenericRead), "generic read mapping");

                string code;
                AssertEx.True(EngineServiceBoundary.TryValidatePipeClientAccess(EngineServiceBoundary.PipeClientAccess, out code), "exact mask");
                AssertEx.False(
                    EngineServiceBoundary.TryValidatePipeClientAccess(
                        EngineServiceBoundary.PipeClientAccess | 0x00000004U,
                        out code),
                    "widened mask");
                AssertEx.False(
                    EngineServiceBoundary.TryValidatePipeClientAccess(
                        EngineServiceBoundary.GenericWrite,
                        out code),
                    "generic write");
            });

            runner.Check("service boundary: the pipe SDDL names only SYSTEM, Administrators, and the user", delegate
            {
                string sddl;
                AssertEx.True(EngineServiceBoundary.TryBuildPipeSddl(UserSid, out sddl), "build");
                AssertEx.Equal(
                    "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120183;;;" + UserSid + ")",
                    sddl,
                    "pipe SDDL");
                AssertEx.DoesNotContain(sddl, "WD", "no Everyone");
                AssertEx.DoesNotContain(sddl, "AU", "no Authenticated Users");
                AssertEx.DoesNotContain(sddl, "IU", "no Interactive");
                AssertEx.DoesNotContain(sddl, "AN", "no Anonymous");
            });

            runner.Check("service boundary: the service SDDL grants query config and not change config", delegate
            {
                string sddl;
                AssertEx.True(EngineServiceBoundary.TryBuildServiceSddl(UserSid, out sddl), "build");
                AssertEx.Contains(sddl, "(A;;0xB5;;;" + UserSid + ")", "service rights");
                AssertEx.Equal(0x000000B5U, EngineServiceBoundary.ServiceClientAccess, "service mask");
                AssertEx.Equal(
                    EngineServiceBoundary.ServiceClientAccess,
                    EngineServiceBoundary.ServiceClientAccess & ~EngineServiceBoundary.ServiceChangeConfig,
                    "no change config");
                string code;
                AssertEx.True(
                    EngineServiceBoundary.TryValidateServiceClientAccess(
                        EngineServiceBoundary.ServiceClientAccess,
                        out code),
                    "valid service mask");
                AssertEx.False(
                    EngineServiceBoundary.TryValidateServiceClientAccess(
                        EngineServiceBoundary.ServiceClientAccess | EngineServiceBoundary.ServiceChangeConfig,
                        out code),
                    "change config refused");
            });

            runner.Check("service boundary: a numeric SID is required and injection is refused", delegate
            {
                AssertEx.True(EngineServiceBoundary.IsValidUserSid(UserSid), "valid SID");
                AssertEx.True(EngineServiceBoundary.IsValidUserSid(EngineServiceBoundary.SystemSid), "SYSTEM SID");
                AssertEx.False(
                    EngineServiceBoundary.IsValidUserSid("S-1-5-21-1)(A;;GA;;;WD"),
                    "parenthesis");
                AssertEx.False(EngineServiceBoundary.IsValidUserSid("S-1-5-21-01"), "leading zero");
                AssertEx.False(EngineServiceBoundary.IsValidUserSid("S-1-5-21-1;"), "separator");
                AssertEx.False(EngineServiceBoundary.IsValidUserSid("S-1-5-21-1 "), "space");
                string sddl;
                AssertEx.False(EngineServiceBoundary.TryBuildPipeSddl("S-1-5-21-1)", out sddl), "bad SID refused");
            });

            runner.Check("service caller: the same account is allowed and another account is denied", delegate
            {
                EngineServiceCallerPolicy policy = new EngineServiceCallerPolicy(UserSid);
                EngineServiceCallerVerdict allowed = policy.Evaluate(new EngineServiceCallerIdentity(
                    UserSid,
                    2,
                    EngineServiceImpersonationLevel.Identification,
                    "",
                    false));
                AssertEx.True(allowed.Allowed, "same user");
                AssertEx.Equal("same_user_caller", allowed.EventCode, "event");

                EngineServiceCallerVerdict elevated = policy.Evaluate(new EngineServiceCallerIdentity(
                    UserSid,
                    2,
                    EngineServiceImpersonationLevel.Impersonation,
                    "",
                    true));
                AssertEx.True(elevated.Allowed, "elevated same user");
                AssertEx.Equal("elevated_caller", elevated.EventCode, "elevated event");

                EngineServiceCallerVerdict other = policy.Evaluate(new EngineServiceCallerIdentity(
                    "S-1-5-21-1111111111-2222222222-3333333333-1002",
                    2,
                    EngineServiceImpersonationLevel.Identification,
                    "",
                    false));
                AssertEx.False(other.Allowed, "other user");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BoundaryAuthFailed, other.Code, "other code");
            });

            runner.Check("service caller: a low impersonation level, a bad session, and a null caller are denied", delegate
            {
                EngineServiceCallerPolicy policy = new EngineServiceCallerPolicy(UserSid);
                EngineServiceCallerVerdict anonymous = policy.Evaluate(new EngineServiceCallerIdentity(
                    UserSid,
                    2,
                    EngineServiceImpersonationLevel.Anonymous,
                    "",
                    false));
                AssertEx.False(anonymous.Allowed, "anonymous");
                AssertEx.Equal("caller_impersonation_too_low", anonymous.EventCode, "anonymous event");

                EngineServiceCallerVerdict noSession = policy.Evaluate(new EngineServiceCallerIdentity(
                    UserSid,
                    0,
                    EngineServiceImpersonationLevel.Identification,
                    "",
                    false));
                AssertEx.False(noSession.Allowed, "no session");
                AssertEx.Equal("caller_session_invalid", noSession.EventCode, "session event");

                EngineServiceCallerVerdict missing = policy.Evaluate(null);
                AssertEx.False(missing.Allowed, "null");
                AssertEx.Equal("caller_missing", missing.EventCode, "null event");
            });

            runner.Check("service caller: an optional package family is checked exactly", delegate
            {
                EngineServiceCallerPolicy policy = new EngineServiceCallerPolicy(UserSid, "Example.App_123");
                EngineServiceCallerVerdict match = policy.Evaluate(new EngineServiceCallerIdentity(
                    UserSid,
                    3,
                    EngineServiceImpersonationLevel.Identification,
                    "Example.App_123",
                    false));
                AssertEx.True(match.Allowed, "matching package");
                EngineServiceCallerVerdict mismatch = policy.Evaluate(new EngineServiceCallerIdentity(
                    UserSid,
                    3,
                    EngineServiceImpersonationLevel.Identification,
                    "Other.App_456",
                    false));
                AssertEx.False(mismatch.Allowed, "other package");
                AssertEx.Equal("caller_package_mismatch", mismatch.EventCode, "package event");
            });

            runner.Check("service caller: the same-user limit is stated in plain words", delegate
            {
                string text = EngineServiceCallerPolicy.SameUserStatement();
                AssertEx.Contains(text, "Any process running as the installing account", "same user");
                AssertEx.Contains(text, "cannot read the bearer secret", "secret");
                AssertEx.Contains(text, "not one process", "limit");
                AssertEx.Contains(text, "does not block", "allowed not blocked");
                AssertEx.Contains(text, "Remote clients are rejected", "remote clients");
                AssertEx.Contains(text, "PIPE_REJECT_REMOTE_CLIENTS", "remote flag");
            });

            runner.Check("service boundary: the server pipe policy requires one overlapped byte-mode instance", delegate
            {
                AssertEx.Equal(0x00000008U, EngineServiceBoundary.PipeRejectRemoteClients, "reject remote");
                AssertEx.Equal(0x00080000U, EngineServiceBoundary.FileFlagFirstPipeInstance, "first instance");
                AssertEx.Equal(0x40000000U, EngineServiceBoundary.FileFlagOverlapped, "overlapped");
                AssertEx.Equal(0x00000000U, EngineServiceBoundary.PipeTypeByte, "byte type");
                AssertEx.Equal(0x00000000U, EngineServiceBoundary.PipeReadmodeByte, "byte read mode");
                AssertEx.Equal(0x00000000U, EngineServiceBoundary.PipeWait, "wait mode");
                AssertEx.Equal(1, EngineServiceBoundary.PipeServerMaxInstances, "one instance");
                AssertEx.Equal(255, EngineServiceBoundary.PipeUnlimitedInstances, "unlimited value");
                AssertEx.True(
                    (EngineServiceBoundary.PipeServerOpenMode
                        & EngineServiceBoundary.FileFlagFirstPipeInstance) != 0,
                    "server open mode has first instance");
                AssertEx.True(
                    (EngineServiceBoundary.PipeServerOpenMode
                        & EngineServiceBoundary.FileFlagOverlapped) != 0,
                    "server open mode has overlapped");
                AssertEx.True(
                    (EngineServiceBoundary.PipeServerMode
                        & EngineServiceBoundary.PipeRejectRemoteClients) != 0,
                    "server mode rejects remote");
                AssertEx.Equal(
                    EngineServiceBoundary.PipeRejectRemoteClients,
                    EngineServiceBoundary.PipeServerMode,
                    "server mode is byte, wait, and reject remote");
                AssertEx.Equal(
                    EngineServiceBoundary.PipeAccessDuplex,
                    EngineServiceBoundary.PipeServerOpenMode & EngineServiceBoundary.PipeAccessDuplex,
                    "duplex");

                string code;
                AssertEx.True(
                    EngineServiceBoundary.TryValidatePipeServerCreate(
                        EngineServiceBoundary.PipeServerOpenMode,
                        EngineServiceBoundary.PipeServerMode,
                        EngineServiceBoundary.PipeServerMaxInstances,
                        out code),
                    "exact server policy: " + code);
                AssertEx.False(
                    EngineServiceBoundary.TryValidatePipeServerCreate(
                        EngineServiceBoundary.PipeAccessDuplex | EngineServiceBoundary.FileFlagOverlapped,
                        EngineServiceBoundary.PipeServerMode,
                        1,
                        out code),
                    "missing first instance");
                AssertEx.False(
                    EngineServiceBoundary.TryValidatePipeServerCreate(
                        EngineServiceBoundary.PipeAccessDuplex
                            | EngineServiceBoundary.FileFlagFirstPipeInstance,
                        EngineServiceBoundary.PipeServerMode,
                        1,
                        out code),
                    "missing overlapped");
                AssertEx.False(
                    EngineServiceBoundary.TryValidatePipeServerCreate(
                        EngineServiceBoundary.PipeServerOpenMode,
                        0,
                        1,
                        out code),
                    "missing remote rejection");
                AssertEx.False(
                    EngineServiceBoundary.TryValidatePipeServerCreate(
                        EngineServiceBoundary.PipeServerOpenMode,
                        EngineServiceBoundary.PipeServerMode | EngineServiceBoundary.PipeNowait,
                        1,
                        out code),
                    "nowait mode");
                AssertEx.False(
                    EngineServiceBoundary.TryValidatePipeServerCreate(
                        EngineServiceBoundary.PipeServerOpenMode,
                        EngineServiceBoundary.PipeServerMode
                            | EngineServiceBoundary.PipeReadmodeMessage,
                        1,
                        out code),
                    "message read mode");
                AssertEx.False(
                    EngineServiceBoundary.TryValidatePipeServerCreate(
                        EngineServiceBoundary.PipeServerOpenMode,
                        EngineServiceBoundary.PipeServerMode
                            | EngineServiceBoundary.PipeTypeMessage,
                        1,
                        out code),
                    "message type");
                AssertEx.False(
                    EngineServiceBoundary.TryValidatePipeServerCreate(
                        EngineServiceBoundary.PipeServerOpenMode,
                        EngineServiceBoundary.PipeServerMode | 0x00001000U,
                        1,
                        out code),
                    "unknown pipe mode bit");
                AssertEx.False(
                    EngineServiceBoundary.TryValidatePipeServerCreate(
                        EngineServiceBoundary.PipeServerOpenMode,
                        EngineServiceBoundary.PipeServerMode,
                        2,
                        out code),
                    "two instances");
                AssertEx.False(
                    EngineServiceBoundary.TryValidatePipeServerCreate(
                        EngineServiceBoundary.PipeServerOpenMode,
                        EngineServiceBoundary.PipeServerMode,
                        EngineServiceBoundary.PipeUnlimitedInstances,
                        out code),
                    "unlimited instances");
            });

            runner.Check("service boundary: a well-known group, service, or authority SID cannot become the user ACE", delegate
            {
                AssertEx.True(EngineServiceBoundary.IsValidUserSid(UserSid), "user syntax");
                AssertEx.True(EngineServiceBoundary.IsValidUserSid(EngineServiceBoundary.SystemSid), "SYSTEM syntax");
                AssertEx.False(EngineServiceBoundary.IsValidUserSid("S-1-5"), "no sub-authority");
                AssertEx.True(EngineServiceBoundary.IsAllowedPipeUserSid(UserSid), "allowed user");
                AssertEx.False(
                    EngineServiceBoundary.IsAllowedPipeUserSid(EngineServiceBoundary.SystemSid),
                    "SYSTEM is not the installing person");
                AssertEx.False(
                    EngineServiceBoundary.IsAllowedPipeUserSid(EngineServiceBoundary.AdministratorsSid),
                    "Administrators is a group");
                AssertEx.False(EngineServiceBoundary.IsAllowedPipeUserSid("S-1-1-0"), "Everyone");
                AssertEx.False(EngineServiceBoundary.IsAllowedPipeUserSid("S-1-5-11"), "Authenticated Users");
                AssertEx.False(EngineServiceBoundary.IsAllowedPipeUserSid("S-1-5-32-545"), "Users");
                AssertEx.False(EngineServiceBoundary.IsAllowedPipeUserSid("S-1-5-21-1-2-3"), "short account");
                // The form check cannot tell a custom group from a user. The
                // future host must add LookupAccountSid and require SidTypeUser.
                AssertEx.True(
                    EngineServiceBoundary.IsAllowedPipeUserSid(
                        "S-1-5-21-1111111111-2222222222-3333333333-512"),
                    "custom account-form SID passes the form check");

                string sddl;
                AssertEx.False(
                    EngineServiceBoundary.TryBuildPipeSddl(EngineServiceBoundary.SystemSid, out sddl),
                    "SYSTEM ACE refused");
                AssertEx.False(
                    EngineServiceBoundary.TryBuildPipeSddl("S-1-1-0", out sddl),
                    "Everyone ACE refused");
                AssertEx.False(
                    EngineServiceBoundary.TryBuildServiceSddl(EngineServiceBoundary.AdministratorsSid, out sddl),
                    "Administrators service ACE refused");

                bool threw = false;
                try
                {
                    new EngineServiceCallerPolicy("S-1-1-0");
                }
                catch (ArgumentException)
                {
                    threw = true;
                }
                AssertEx.True(threw, "caller policy refuses Everyone");
            });

            runner.Check("service caller: Win32 impersonation levels map exactly", delegate
            {
                EngineServiceImpersonationLevel level;
                AssertEx.True(
                    EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(0, out level),
                    "anonymous maps");
                AssertEx.Equal(EngineServiceImpersonationLevel.Anonymous, level, "anonymous");
                AssertEx.True(
                    EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(1, out level),
                    "identification maps");
                AssertEx.Equal(EngineServiceImpersonationLevel.Identification, level, "identification");
                AssertEx.True(
                    EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(2, out level),
                    "impersonation maps");
                AssertEx.Equal(EngineServiceImpersonationLevel.Impersonation, level, "impersonation");
                AssertEx.True(
                    EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(3, out level),
                    "delegation maps");
                AssertEx.Equal(EngineServiceImpersonationLevel.Delegation, level, "delegation");
                AssertEx.False(
                    EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(4, out level),
                    "value 4 is not a Win32 level");
                AssertEx.Equal(EngineServiceImpersonationLevel.Unreadable, level, "unreadable");
                AssertEx.False(
                    EngineServiceCallerPolicy.TryMapWin32ImpersonationLevel(-1, out level),
                    "negative is not a Win32 level");
                AssertEx.Equal(-1, (int)EngineServiceImpersonationLevel.None, "legacy none");
                AssertEx.Equal(
                    (int)EngineServiceImpersonationLevel.Unreadable,
                    (int)EngineServiceImpersonationLevel.None,
                    "none aliases unreadable");

                EngineServiceCallerPolicy policy = new EngineServiceCallerPolicy(UserSid);
                EngineServiceCallerVerdict identified = policy.Evaluate(new EngineServiceCallerIdentity(
                    UserSid,
                    2,
                    EngineServiceImpersonationLevel.Identification,
                    "",
                    false));
                AssertEx.True(identified.Allowed, "identification is enough");
                EngineServiceCallerVerdict unreadable = policy.Evaluate(new EngineServiceCallerIdentity(
                    UserSid,
                    2,
                    EngineServiceImpersonationLevel.None,
                    "",
                    false));
                AssertEx.False(unreadable.Allowed, "legacy none is denied");
                AssertEx.Equal("caller_impersonation_unreadable", unreadable.EventCode, "unreadable event");
                EngineServiceCallerVerdict invalid = policy.Evaluate(new EngineServiceCallerIdentity(
                    UserSid,
                    2,
                    (EngineServiceImpersonationLevel)9,
                    "",
                    false));
                AssertEx.False(invalid.Allowed, "undefined enum is denied");
                AssertEx.Equal("caller_impersonation_invalid", invalid.EventCode, "invalid event");
            });

            runner.Check("service caller: a failed revert closes the connection and stops from a clean thread", delegate
            {
                EngineServiceRevertDecision failed = EngineServiceRevertDecision.AfterRevert(false);
                AssertEx.False(failed.Allowed, "not allowed");
                AssertEx.True(failed.CloseConnection, "close");
                AssertEx.True(failed.StopTunnel, "stop");
                AssertEx.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, failed.Code, "code");
                AssertEx.Equal("revert_failed", failed.EventCode, "event");

                EngineServiceRevertDecision reverted = EngineServiceRevertDecision.AfterRevert(true);
                AssertEx.True(reverted.Allowed, "allowed");
                AssertEx.False(reverted.CloseConnection, "no close");
                AssertEx.False(reverted.StopTunnel, "no stop");

                string rule = EngineServiceRevertDecision.RuleText();
                AssertEx.Contains(rule, "never impersonated", "clean thread");
                AssertEx.Contains(rule, "parse no frame", "no parse");
                AssertEx.Contains(rule, "send no reply", "no reply");
            });

            runner.Check("service state: a never-launched record is the only clean start", delegate
            {
                DateTimeOffset now = Now();
                EngineServiceStateRecord record = EngineServiceStateRecord.CreateNeverLaunched(now);
                string code;
                AssertEx.True(record.Validate(out code), "valid: " + code);
                AssertEx.True(record.CanStart(out code), "can start: " + code);
                AssertEx.Equal(EngineServicePhase.NeverLaunched, record.Phase, "phase");
                AssertEx.Equal(EngineServiceCleanup.Ok, record.Cleanup, "cleanup");
                AssertEx.False(record.RoutesMayExist, "no routes");
            });

            runner.Check("service state: a launch intent blocks a start and records the gate", delegate
            {
                DateTimeOffset now = Now();
                EngineServiceStateRecord record = EngineServiceStateRecord.CreateNeverLaunched(
                        now,
                        "C:\\Program Files\\HotspotShade\\hotspotshade.exe")
                    .BeginLaunch("intent-0001", Nonce(), "HotspotShade-test-1", GuidText(), 123, now);
                string code;
                AssertEx.True(record.Validate(out code), "valid: " + code);
                AssertEx.False(record.CanStart(out code), "start blocked");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "code");
                AssertEx.Equal(EngineServicePhase.Launching, record.Phase, "phase");
                AssertEx.False(record.RoutesMayExist, "no routes before the adapter");
            });

            runner.Check("service state: the adapter gate precedes the running state", delegate
            {
                DateTimeOffset now = Now();
                EngineServiceStateRecord launching = NewLaunching(now);
                EngineServiceStateRecord launched = launching.MarkLaunched(1234, 5678, now);
                AssertEx.Equal(EngineServicePhase.Launched, launched.Phase, "launched");
                AssertEx.False(launched.RoutesMayExist, "no routes yet");
                string code;
                AssertEx.True(launched.Validate(out code), "launched valid: " + code);

                string observed = GuidText();
                EngineServiceStateRecord ready = launched.MarkAdapterReady(42, observed, now);
                AssertEx.Equal(EngineServicePhase.AdapterReady, ready.Phase, "adapter ready");
                AssertEx.True(ready.RoutesMayExist, "routes may exist");
                AssertEx.Equal(EngineServiceIdentitySource.Observed, ready.IdentitySource, "observed");
                AssertEx.Equal(42UL, ready.AdapterLuid, "luid");
                AssertEx.Equal(observed, ready.AdapterGuid, "guid");

                EngineServiceStateRecord running = ready.MarkRunning(now);
                AssertEx.Equal(EngineServicePhase.Running, running.Phase, "running");
                AssertEx.True(running.Validate(out code), "running valid: " + code);
                AssertEx.False(running.CanStart(out code), "no second start");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "running code");
            });

            runner.Check("service state: a clean stop allows a later start and failed cleanup blocks it", delegate
            {
                DateTimeOffset now = Now();
                EngineServiceStateRecord running = NewRunning(now);
                EngineServiceStateRecord stopping = running.BeginStopping(now);
                AssertEx.Equal(EngineServicePhase.Stopping, stopping.Phase, "stopping");
                AssertEx.Equal(EngineServiceCleanup.Pending, stopping.Cleanup, "pending");

                EngineServiceStateRecord stopped = stopping.MarkStopped(
                    EngineServiceStopReason.User,
                    EngineServiceCleanup.Ok,
                    now);
                AssertEx.Equal(EngineServicePhase.Stopped, stopped.Phase, "stopped");
                AssertEx.False(stopped.RoutesMayExist, "clean routes");
                string code;
                AssertEx.True(stopped.CanStart(out code), "start after clean stop: " + code);

                EngineServiceStateRecord failed = stopping.MarkStopped(
                    EngineServiceStopReason.Unknown,
                    EngineServiceCleanup.Failed,
                    now);
                AssertEx.Equal(EngineServicePhase.CleanupFailed, failed.Phase, "failed");
                AssertEx.True(failed.RoutesMayExist, "pessimistic routes");
                AssertEx.False(failed.CanStart(out code), "failed start blocked");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupBlocked, code, "failed code");

                EngineServiceStateRecord unknown = stopping.MarkStopped(
                    EngineServiceStopReason.Unknown,
                    EngineServiceCleanup.Unknown,
                    now);
                AssertEx.Equal(EngineServicePhase.CleanupUnknown, unknown.Phase, "unknown");
                AssertEx.True(unknown.RoutesMayExist, "unknown routes");
                AssertEx.False(unknown.CanStart(out code), "unknown start blocked");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "unknown code");
            });

            runner.Check("service state: a clean stopped record with a process needs an identity proof", delegate
            {
                DateTimeOffset now = Now();
                EngineServiceStateRecord stopped = NewRunning(now)
                    .BeginStopping(now)
                    .MarkStopped(EngineServiceStopReason.User, EngineServiceCleanup.Ok, now);
                AssertEx.Equal(EngineServicePhase.Stopped, stopped.Phase, "stopped");
                AssertEx.Equal(EngineServiceCleanup.Ok, stopped.Cleanup, "clean");
                AssertEx.Equal(1234, stopped.Pid, "recorded pid");
                AssertEx.True(stopped.Created100ns > 0, "recorded creation time");

                string code;
                EngineServiceStateGate noProof =
                    EngineServiceStateGate.FromRecord(stopped);
                AssertEx.False(noProof.CanStart(out code), "no proof refuses");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "no proof code");

                EngineServiceStateGate alive = EngineServiceStateGate.FromRecord(
                    stopped,
                    new FakeProcessProof(EngineServiceRecordedProcessState.Alive));
                AssertEx.False(alive.CanStart(out code), "alive process refuses");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupPending, code, "alive code");

                EngineServiceStateGate unknown = EngineServiceStateGate.FromRecord(
                    stopped,
                    new FakeProcessProof(EngineServiceRecordedProcessState.Unknown));
                AssertEx.False(unknown.CanStart(out code), "unknown proof refuses");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "unknown code");

                EngineServiceStateGate throwing = EngineServiceStateGate.FromRecord(
                    stopped,
                    new ThrowingProcessProof());
                AssertEx.False(throwing.CanStart(out code), "throwing proof refuses");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "throwing code");

                EngineServiceStateGate gone = EngineServiceStateGate.FromRecord(
                    stopped,
                    new FakeProcessProof(EngineServiceRecordedProcessState.Gone));
                AssertEx.True(gone.CanStart(out code), "gone process starts: " + code);

                EngineServiceStateGate loaded;
                AssertEx.True(
                    EngineServiceStateGate.TryLoad(
                        true,
                        true,
                        stopped.ToFields(),
                        new FakeProcessProof(EngineServiceRecordedProcessState.Gone),
                        out loaded,
                        out code),
                    "loaded with proof: " + code);
                AssertEx.True(loaded.CanStart(out code), "loaded proof starts: " + code);

                AssertEx.True(
                    EngineServiceStateGate.TryLoad(
                        true,
                        true,
                        stopped.ToFields(),
                        out loaded,
                        out code),
                    "loaded without proof: " + code);
                AssertEx.False(loaded.CanStart(out code), "loaded record still needs proof");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "loaded code");

                EngineServiceStateRecord notStarted = NewLaunching(now).MarkLaunchNotStarted(now);
                AssertEx.Equal(0, notStarted.Pid, "no process recorded");
                AssertEx.True(
                    EngineServiceStateGate.FromRecord(notStarted).CanStart(out code),
                    "a proven not-started launch needs no process proof: " + code);
            });

            runner.Check("service state: a proven not-started launch has no effect and can be retried", delegate
            {
                DateTimeOffset now = Now();
                EngineServiceStateRecord launching = NewLaunching(now);
                EngineServiceStateRecord failed = launching.MarkLaunchNotStarted(now);
                AssertEx.Equal(EngineServicePhase.Stopped, failed.Phase, "stopped");
                AssertEx.Equal(EngineServiceCleanup.Ok, failed.Cleanup, "clean");
                AssertEx.Equal(EngineServiceStopReason.StartFailed, failed.Stop, "reason");
                AssertEx.False(failed.RoutesMayExist, "no routes");
                string code;
                AssertEx.True(failed.CanStart(out code), "retry allowed: " + code);

                bool threw = false;
                try
                {
                    NewLaunching(now).MarkLaunched(1234, 5678, now).MarkLaunchNotStarted(now);
                }
                catch (InvalidOperationException)
                {
                    threw = true;
                }
                AssertEx.True(threw, "a launched process is not a not-started launch");
            });

            runner.Check("service state: a launch record without a process proof is cleanup unknown", delegate
            {
                DateTimeOffset now = Now();
                EngineServiceStateRecord failed = NewLaunching(now).MarkLaunchFailed(now);
                AssertEx.Equal(EngineServicePhase.CleanupUnknown, failed.Phase, "unknown phase");
                AssertEx.Equal(EngineServiceCleanup.Unknown, failed.Cleanup, "unknown cleanup");
                AssertEx.Equal(EngineServiceStopReason.StartFailed, failed.Stop, "reason");
                AssertEx.False(failed.RoutesMayExist, "no route was acknowledged");
                string code;
                AssertEx.False(failed.CanStart(out code), "start blocked");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "unknown code");
            });

            runner.Check("service state: a failed launched process is never clean without proof", delegate
            {
                DateTimeOffset now = Now();
                EngineServiceStateRecord launched = NewLaunching(now).MarkLaunched(1234, 5678, now);
                EngineServiceStateRecord failed = launched.MarkLaunchFailed(now);
                AssertEx.Equal(EngineServicePhase.CleanupUnknown, failed.Phase, "unknown phase");
                AssertEx.Equal(EngineServiceCleanup.Unknown, failed.Cleanup, "unknown cleanup");
                AssertEx.Equal(EngineServiceStopReason.StartFailed, failed.Stop, "reason");
                AssertEx.True(failed.RoutesMayExist, "routes may exist");
                AssertEx.Equal(1234, failed.Pid, "pid kept");
                string code;
                AssertEx.False(failed.CanStart(out code), "start blocked");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "unknown code");

                EngineServiceStateRecord parsed;
                AssertEx.True(
                    EngineServiceStateRecord.TryParse(failed.ToFields(), out parsed, out code),
                    "round trip: " + code);
                AssertEx.Equal(EngineServicePhase.CleanupUnknown, parsed.Phase, "parsed phase");
                AssertEx.True(parsed.RoutesMayExist, "parsed routes");
            });

            runner.Check("service state: a missing or unreadable durable record blocks every start", delegate
            {
                DateTimeOffset now = Now();
                EngineServiceStateGate gate;
                string code;
                AssertEx.False(
                    EngineServiceStateGate.TryLoad(false, true, null, out gate, out code),
                    "missing record");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "missing code");
                AssertEx.False(gate.HasRecord, "missing has no record");
                AssertEx.False(gate.CanStart(out code), "missing blocks start");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "missing start code");

                AssertEx.False(
                    EngineServiceStateGate.TryLoad(true, false, null, out gate, out code),
                    "unreadable record");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "unreadable code");
                AssertEx.False(gate.CanStart(out code), "unreadable blocks start");

                Dictionary<string, string> fields = EngineServiceStateRecord.CreateNeverLaunched(now).ToFields();
                AssertEx.True(
                    EngineServiceStateGate.TryLoad(true, true, fields, out gate, out code),
                    "readable record: " + code);
                AssertEx.True(gate.HasRecord, "readable has record");
                AssertEx.True(gate.CanStart(out code), "clean record starts: " + code);

                Dictionary<string, string> version = new Dictionary<string, string>(fields);
                version[EngineServiceStateKeys.Version] = "2";
                AssertEx.False(
                    EngineServiceStateGate.TryLoad(true, true, version, out gate, out code),
                    "version mismatch");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "version code");

                Dictionary<string, string> damaged = new Dictionary<string, string>(fields);
                damaged.Remove(EngineServiceStateKeys.Phase);
                AssertEx.False(
                    EngineServiceStateGate.TryLoad(true, true, damaged, out gate, out code),
                    "damaged record");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "damaged code");

                AssertEx.True(
                    EngineServiceStateGate.TryLoad(true, true, NewRunning(now).ToFields(), out gate, out code),
                    "running record loads");
                AssertEx.False(gate.CanStart(out code), "running record blocks");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "running code");
            });

            runner.Check("service state: a missing final frame is cleanup unknown and never clean", delegate
            {
                DateTimeOffset now = Now();
                EngineServiceStateRecord launching = NewLaunching(now);
                EngineServiceStateRecord unknown = launching.MarkCleanupUnknown(now);
                AssertEx.Equal(EngineServicePhase.CleanupUnknown, unknown.Phase, "phase");
                AssertEx.Equal(EngineServiceCleanup.Unknown, unknown.Cleanup, "cleanup");
                AssertEx.Equal(EngineServiceStopReason.Unknown, unknown.Stop, "reason");
                AssertEx.False(unknown.RoutesMayExist, "no routes were possible");
                string code;
                AssertEx.False(unknown.CanStart(out code), "start blocked");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, code, "code");
            });

            runner.Check("service state: a record round trips without a secret", delegate
            {
                DateTimeOffset now = Now();
                EngineServiceStateRecord running = NewRunning(now);
                Dictionary<string, string> fields = running.ToFields();
                AssertEx.True(fields.Count <= EngineProtocol.MaxFieldCount, "field count");
                string code;
                AssertEx.True(EngineWire.TryValidateFields(fields, out code), "wire fields: " + code);
                foreach (string key in fields.Keys)
                {
                    AssertEx.False(EngineProtocol.IsCredentialKey(key), "credential key " + key);
                }
                foreach (string key in EngineServiceStateKeys.AllFields())
                {
                    AssertEx.False(
                        EngineProtocol.IsCredentialKey(key),
                        "state field must be non-secret: " + key);
                }
                AssertEx.False(
                    EngineProtocol.IsCredentialKey(EngineServiceStateKeys.LaunchNonce),
                    "launch_nonce is non-secret correlation data");
                AssertEx.False(
                    EngineServiceStateRecord.HasCredentialField(fields),
                    "no credential field is serialized");

                EngineServiceStateRecord parsed;
                AssertEx.True(EngineServiceStateRecord.TryParse(fields, out parsed, out code), "parse: " + code);
                AssertEx.Equal(EngineServicePhase.Running, parsed.Phase, "phase");
                AssertEx.Equal(running.Pid, parsed.Pid, "pid");
                AssertEx.Equal(running.Created100ns, parsed.Created100ns, "created");
                AssertEx.Equal(running.AdapterLuid, parsed.AdapterLuid, "luid");
                AssertEx.Equal(running.AdapterGuid, parsed.AdapterGuid, "guid");
                AssertEx.Equal(running.Cleanup, parsed.Cleanup, "cleanup");
                AssertEx.Equal(running.LaunchNonce, parsed.LaunchNonce, "nonce");

                Dictionary<string, string> bearer = new Dictionary<string, string>(fields);
                bearer["bearer"] = "a-serialized-bearer-is-refused";
                AssertEx.True(
                    EngineServiceStateRecord.HasCredentialField(bearer),
                    "bearer field is detected");
                AssertEx.False(
                    EngineServiceStateRecord.TryParse(bearer, out parsed, out code),
                    "serialized bearer is refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Forbidden, code, "bearer code");
            });

            runner.Check("service state: a bad transition, an unknown field, and a broken handle pair are refused", delegate
            {
                DateTimeOffset now = Now();
                EngineServiceStateRecord initial = EngineServiceStateRecord.CreateNeverLaunched(now);
                bool threw = false;
                try
                {
                    initial.MarkRunning(now);
                }
                catch (InvalidOperationException)
                {
                    threw = true;
                }
                AssertEx.True(threw, "running without launch");

                Dictionary<string, string> fields = initial.ToFields();
                fields["surprise"] = "value";
                EngineServiceStateRecord parsed;
                string code;
                AssertEx.False(EngineServiceStateRecord.TryParse(fields, out parsed, out code), "unknown field");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadRequest, code, "unknown code");

                Dictionary<string, string> broken = NewRunning(now).ToFields();
                broken.Remove(EngineServiceStateKeys.Created100ns);
                AssertEx.False(EngineServiceStateRecord.TryParse(broken, out parsed, out code), "missing creation time");
            });

            runner.Check("service status: a running phase 2 status parses with both counts separate", delegate
            {
                DateTimeOffset now = Now();
                Dictionary<string, string> fields = RunningStatusFields(now);
                EngineServiceStatus status;
                string code;
                AssertEx.True(EngineServiceStatus.TryParse(fields, now, out status, out code), "parse: " + code);
                AssertEx.True(status.Running, "running");
                AssertEx.Equal(EngineRunState.Running, status.Engine, "engine");
                AssertEx.Equal(EngineServicePairedScope.Identity, status.PairedScope, "scope");
                AssertEx.Equal(3, status.PhoneConnections.Value, "source count");
                AssertEx.Equal(7, status.RelayTcpFlowsActive.Value, "relay count");
                AssertEx.Equal(0, status.TtlBad, "ttl audit");
                AssertEx.Equal(EngineServiceCleanup.Unknown, status.Cleanup, "cleanup");
            });

            runner.Check("service status: a stopped status leaves both counts unknown", delegate
            {
                DateTimeOffset now = Now();
                Dictionary<string, string> fields = StoppedStatusFields(now);
                EngineServiceStatus status;
                string code;
                AssertEx.True(EngineServiceStatus.TryParse(fields, now, out status, out code), "parse: " + code);
                AssertEx.False(status.Running, "stopped");
                AssertEx.False(status.PhoneConnections.HasValue, "source count unknown");
                AssertEx.False(status.RelayTcpFlowsActive.HasValue, "relay count unknown");
                AssertEx.Equal(EngineServiceCleanup.Ok, status.Cleanup, "cleanup");
                AssertEx.Equal(EngineServiceStopReason.User, status.Stop, "stop");
            });

            runner.Check("service status: a stopped count, a missing check time, and a wrong pairing are refused", delegate
            {
                DateTimeOffset now = Now();
                Dictionary<string, string> counted = StoppedStatusFields(now);
                counted[EngineServiceStatusKeys.RelayTcpFlowsActive] = "0";
                counted[EngineServiceStatusKeys.RelayTcpFlowsActiveKnown] = "1";
                AssertStatusRefused(counted, now, "stopped count");

                Dictionary<string, string> pairedStop = StoppedStatusFields(now);
                pairedStop[EngineServiceStatusKeys.Paired] = "1";
                pairedStop[EngineServiceStatusKeys.PairedScope] = "session";
                AssertStatusRefused(pairedStop, now, "phase-one stop with pairing");

                Dictionary<string, string> identityStop = StoppedStatusFields(now);
                identityStop[EngineServiceStatusKeys.Paired] = "1";
                identityStop[EngineServiceStatusKeys.PairedScope] = "identity";
                EngineServiceStatus phaseTwo;
                string phaseTwoCode;
                AssertEx.True(
                    EngineServiceStatus.TryParse(identityStop, now, out phaseTwo, out phaseTwoCode),
                    "phase two stop: " + phaseTwoCode);
                AssertEx.True(phaseTwo.Paired, "phase two pairing kept");
                AssertEx.Equal(
                    EngineServicePairedScope.Identity,
                    phaseTwo.PairedScope,
                    "phase two scope");

                Dictionary<string, string> noCheck = RunningStatusFields(now);
                noCheck[EngineServiceStatusKeys.CheckedAt] = "";
                AssertStatusRefused(noCheck, now, "missing check time");

                Dictionary<string, string> unpaired = RunningStatusFields(now);
                unpaired[EngineServiceStatusKeys.Paired] = "0";
                unpaired[EngineServiceStatusKeys.PairedScope] = "none";
                AssertStatusRefused(unpaired, now, "running without pairing");

                Dictionary<string, string> sessionCount = RunningStatusFields(now);
                sessionCount[EngineServiceStatusKeys.PairedScope] = "session";
                AssertStatusRefused(sessionCount, now, "phone count in session scope");

                Dictionary<string, string> noSource = RunningStatusFields(now);
                noSource[EngineServiceStatusKeys.Source] = "0";
                noSource[EngineServiceStatusKeys.Trusted] = "1";
                AssertStatusRefused(noSource, now, "trust without source");

                Dictionary<string, string> runningClean = RunningStatusFields(now);
                runningClean[EngineServiceStatusKeys.Cleanup] = "ok";
                AssertStatusRefused(runningClean, now, "running with clean cleanup");

                Dictionary<string, string> future = RunningStatusFields(now);
                future[EngineServiceStatusKeys.CheckedAt] =
                    (now.ToUnixTimeSeconds() + 301).ToString(CultureInfo.InvariantCulture);
                AssertStatusRefused(future, now, "future check time");

                Dictionary<string, string> unknown = RunningStatusFields(now);
                unknown["surprise"] = "value";
                AssertStatusRefused(unknown, now, "unknown field");
            });

            runner.Check("service status: ok=0 and timestamps beyond the explicit skew are refused", delegate
            {
                DateTimeOffset now = Now();
                AssertEx.Equal(300, EngineServiceStatus.MaxFutureSkewSeconds, "explicit skew");

                Dictionary<string, string> failure = StoppedStatusFields(now);
                failure[EngineServiceStatusKeys.Ok] = "0";
                AssertStatusRefused(failure, now, "ok=0 status");

                Dictionary<string, string> failureWithCode = StoppedStatusFields(now);
                failureWithCode[EngineServiceStatusKeys.Ok] = "0";
                failureWithCode[EngineProtocol.Keys.Code] = EngineProtocol.ErrorCodes.CleanupUnknown;
                AssertStatusRefused(failureWithCode, now, "ok=0 failure body");

                Dictionary<string, string> badOk = StoppedStatusFields(now);
                badOk[EngineServiceStatusKeys.Ok] = "2";
                AssertStatusRefused(badOk, now, "bad ok value");

                Dictionary<string, string> checkedBoundary = RunningStatusFields(now);
                checkedBoundary[EngineServiceStatusKeys.CheckedAt] =
                    (now.ToUnixTimeSeconds() + EngineServiceStatus.MaxFutureSkewSeconds)
                        .ToString(CultureInfo.InvariantCulture);
                EngineServiceStatus status;
                string code;
                AssertEx.True(
                    EngineServiceStatus.TryParse(checkedBoundary, now, out status, out code),
                    "checked_at exactly at the skew: " + code);

                Dictionary<string, string> checkedBeyond = RunningStatusFields(now);
                checkedBeyond[EngineServiceStatusKeys.CheckedAt] =
                    (now.ToUnixTimeSeconds() + EngineServiceStatus.MaxFutureSkewSeconds + 1)
                        .ToString(CultureInfo.InvariantCulture);
                AssertStatusRefused(checkedBeyond, now, "checked_at beyond the skew");

                Dictionary<string, string> stopBoundary = StoppedStatusFields(now);
                stopBoundary[EngineServiceStatusKeys.StopAt] =
                    (now.ToUnixTimeSeconds() + EngineServiceStatus.MaxFutureSkewSeconds)
                        .ToString(CultureInfo.InvariantCulture);
                AssertEx.True(
                    EngineServiceStatus.TryParse(stopBoundary, now, out status, out code),
                    "stop_at exactly at the skew: " + code);

                Dictionary<string, string> stopBeyond = StoppedStatusFields(now);
                stopBeyond[EngineServiceStatusKeys.StopAt] =
                    (now.ToUnixTimeSeconds() + EngineServiceStatus.MaxFutureSkewSeconds + 1)
                        .ToString(CultureInfo.InvariantCulture);
                AssertStatusRefused(stopBeyond, now, "stop_at beyond the skew");
            });

            runner.Check("service status: source freshness uses checked_at, not the read time", delegate
            {
                DateTimeOffset now = Now();
                Dictionary<string, string> fields = ReadyStatusFields(now);
                fields[EngineServiceStatusKeys.CheckedAt] =
                    now.AddSeconds(-20).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                EngineServiceStatus status;
                string code;
                AssertEx.True(
                    EngineServiceStatus.TryParse(fields, now, out status, out code),
                    "old source parse: " + code);
                AssertEx.Equal(EngineFreshness.Unavailable, status.FreshnessAt(now), "old source");

                fields[EngineServiceStatusKeys.CheckedAt] =
                    now.AddSeconds(-5).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                AssertEx.True(
                    EngineServiceStatus.TryParse(fields, now, out status, out code),
                    "stale source parse: " + code);
                AssertEx.Equal(EngineFreshness.Stale, status.FreshnessAt(now), "stale source");

                fields[EngineServiceStatusKeys.CheckedAt] =
                    now.AddSeconds(-1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                AssertEx.True(
                    EngineServiceStatus.TryParse(fields, now, out status, out code),
                    "fresh source parse: " + code);
                AssertEx.Equal(EngineFreshness.Fresh, status.FreshnessAt(now), "fresh source");

                Dictionary<string, string> oldSample = ReadyStatusFields(now);
                oldSample[EngineServiceStatusKeys.CheckedAt] =
                    now.AddSeconds(-19).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                AssertEx.True(
                    EngineServiceStatus.TryParse(
                        oldSample,
                        now.AddSeconds(-20),
                        out status,
                        out code),
                    "old sample parse: " + code);
                AssertEx.Equal(EngineFreshness.Unavailable, status.FreshnessAt(now), "old sample");
            });

            runner.Check("service status: the stop text never turns an unknown observation into a loss claim", delegate
            {
                string text = EngineServiceStatus.StopText(EngineServiceStopReason.ObservationUnavailable);
                AssertEx.Contains(text, "could not check", "unknown text");
                AssertEx.Contains(text, "does not mean", "limit");
                AssertEx.DoesNotContain(text, "hotspot was lost", "no loss claim");
                AssertEx.DoesNotContain(text, "source device stopped", "no source loss claim");
                AssertEx.Equal("observation_unavailable", EngineServiceStatus.StopWord(
                    EngineServiceStopReason.ObservationUnavailable), "word");
            });

            runner.Check("service status: a valid status round trips through the reply reader", delegate
            {
                DateTimeOffset now = Now();
                Dictionary<string, string> fields = RunningStatusFields(now);
                string code;
                EngineReply reply;
                AssertEx.True(
                    EngineServiceReply.TryRead(fields, EngineProtocol.Operations.Status, out reply, out code),
                    "reply: " + code);
                EngineServiceStatus status;
                AssertEx.True(EngineServiceStatus.TryParse(reply.Fields, now, out status, out code), "status: " + code);
                AssertEx.Equal(3, status.PhoneConnections.Value, "count");
            });

            runner.Check("service reply: a hello and a start have their exact shapes", delegate
            {
                string code;
                EngineReply reply;
                Dictionary<string, string> hello = new Dictionary<string, string>(StringComparer.Ordinal);
                hello["v"] = "1";
                hello["ok"] = "1";
                hello["instance"] = "service-0001";
                hello["engine"] = "ready";
                AssertEx.True(
                    EngineServiceReply.TryRead(hello, EngineProtocol.Operations.Hello, out reply, out code),
                    "hello: " + code);

                Dictionary<string, string> start = new Dictionary<string, string>(StringComparer.Ordinal);
                start["v"] = "1";
                start["ok"] = "1";
                AssertEx.True(
                    EngineServiceReply.TryRead(start, EngineProtocol.Operations.Start, out reply, out code),
                    "start: " + code);

                Dictionary<string, string> extra = new Dictionary<string, string>(start);
                extra["instance"] = "service-0001";
                AssertEx.False(
                    EngineServiceReply.TryRead(extra, EngineProtocol.Operations.Start, out reply, out code),
                    "extra start field");
            });

            runner.Check("service reply: a failure, an unknown code, and a success with a code are refused", delegate
            {
                string code;
                EngineReply reply;
                Dictionary<string, string> failure = new Dictionary<string, string>(StringComparer.Ordinal);
                failure["v"] = "1";
                failure["ok"] = "0";
                failure["code"] = EngineProtocol.ErrorCodes.BoundaryAuthFailed;
                AssertEx.True(
                    EngineServiceReply.TryRead(failure, EngineProtocol.Operations.Status, out reply, out code),
                    "failure: " + code);
                AssertEx.False(reply.Ok, "failure ok");

                Dictionary<string, string> unknown = new Dictionary<string, string>(failure);
                unknown["code"] = "not_a_code";
                AssertEx.False(
                    EngineServiceReply.TryRead(unknown, EngineProtocol.Operations.Status, out reply, out code),
                    "unknown code");

                Dictionary<string, string> coded = new Dictionary<string, string>(StringComparer.Ordinal);
                coded["v"] = "1";
                coded["ok"] = "1";
                coded["code"] = EngineProtocol.ErrorCodes.Internal;
                AssertEx.False(
                    EngineServiceReply.TryRead(coded, EngineProtocol.Operations.Start, out reply, out code),
                    "success with a code");
            });

            runner.Check("service client: a status request is framed and the reply is validated", delegate
            {
                DateTimeOffset now = Now();
                Dictionary<string, string> replyFields = RunningStatusFields(now);
                byte[] replyFrame;
                string code;
                AssertEx.True(EngineServiceFrame.TryEncode(replyFields, out replyFrame, out code), "reply frame");
                FakeChannel channel = new FakeChannel();
                channel.Response = replyFrame;
                EngineServiceClient client = new EngineServiceClient(channel, TimeSpan.FromMilliseconds(500));

                EngineReply reply = Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Status, Session, false),
                    CancellationToken.None));

                AssertEx.True(reply.Ok, "reply ok");
                AssertEx.Equal(7, Count(reply.Fields[EngineServiceStatusKeys.RelayTcpFlowsActive]), "relay count");
                AssertEx.Equal(1, channel.Requests.Count, "one request");
                Dictionary<string, string> sent;
                AssertEx.True(
                    EngineServiceFrame.TryDecode(
                        channel.Requests[0],
                        channel.Requests[0].Length,
                        out sent,
                        out code),
                    "request decode");
                AssertEx.Equal("status", sent[EngineProtocol.Keys.Operation], "operation");
                AssertEx.Equal(Session, sent[EngineProtocol.Keys.Session], "session");
            });

            runner.Check("service client: a missing, malformed, or failed channel answer is fixed", delegate
            {
                FakeChannel missing = new FakeChannel();
                EngineServiceClient missingClient = new EngineServiceClient(missing, TimeSpan.FromMilliseconds(500));
                EngineReply missingReply = Wait(missingClient.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Hello, Session, false),
                    CancellationToken.None));
                AssertEx.False(missingReply.Ok, "missing");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadResponse, missingReply.Code, "missing code");
                AssertEx.True(missingReply.OutcomeUnknown, "missing reply leaves delivery unknown");

                FakeChannel malformed = new FakeChannel();
                malformed.Response = new byte[] { 0, 0, 0, 2, 0xC3, 0x28 };
                EngineServiceClient malformedClient = new EngineServiceClient(malformed, TimeSpan.FromMilliseconds(500));
                EngineReply malformedReply = Wait(malformedClient.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Hello, Session, false),
                    CancellationToken.None));
                AssertEx.False(malformedReply.Ok, "malformed");
                AssertEx.Equal(EngineProtocol.ErrorCodes.BadResponse, malformedReply.Code, "malformed code");
                AssertEx.True(malformedReply.OutcomeUnknown, "malformed reply leaves delivery unknown");

                Dictionary<string, string> wrongFields = new Dictionary<string, string>();
                wrongFields["v"] = "1";
                wrongFields["ok"] = "1";
                byte[] wrongFrame;
                string frameCode;
                AssertEx.True(EngineServiceFrame.TryEncode(wrongFields, out wrongFrame, out frameCode), "frame");
                FakeChannel wrongShape = new FakeChannel();
                wrongShape.Response = wrongFrame;
                EngineReply wrongReply = Wait(new EngineServiceClient(wrongShape).SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Hello, Session, false), CancellationToken.None));
                AssertEx.True(wrongReply.OutcomeUnknown, "invalid reply fields leave delivery unknown");

                FakeChannel throwing = new FakeChannel();
                throwing.Throw = true;
                EngineServiceClient throwingClient = new EngineServiceClient(throwing, TimeSpan.FromMilliseconds(500));
                EngineReply throwingReply = Wait(throwingClient.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Hello, Session, false),
                    CancellationToken.None));
                AssertEx.False(throwingReply.Ok, "throwing");
                AssertEx.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, throwingReply.Code, "throwing code");
                AssertEx.True(throwingReply.OutcomeUnknown, "exception leaves delivery unknown");
            });

            runner.Check("service client: a timeout and a close are bounded", delegate
            {
                FakeChannel hanging = new FakeChannel();
                hanging.Hang = true;
                EngineServiceClient client = new EngineServiceClient(hanging, TimeSpan.FromMilliseconds(50));
                EngineReply reply = Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Hello, Session, false),
                    CancellationToken.None));
                AssertEx.False(reply.Ok, "timeout");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Timeout, reply.Code, "timeout code");
                AssertEx.True(reply.OutcomeUnknown, "a channel without evidence cannot prove refusal");

                Wait(client.CloseAsync());
                AssertEx.True(hanging.Closed, "closed");
            });

            runner.Check("service client budgets: a start and a stop outlive the service budget", delegate
            {
                // The service start budget is twenty-five seconds and the stop
                // budget is fifteen. One five second client budget for every
                // operation aborts a start the service is still completing.
                // The service host tests pin the same relationship against the
                // service constants.
                EngineServiceCallBudgets defaults = EngineServiceCallBudgets.Default;
                AssertEx.Equal(
                    TimeSpan.FromSeconds(35),
                    defaults.StartBudget,
                    "start budget");
                AssertEx.Equal(
                    TimeSpan.FromSeconds(25),
                    defaults.StopBudget,
                    "stop budget");
                AssertEx.Equal(
                    TimeSpan.FromSeconds(5),
                    defaults.ShortBudget,
                    "short budget");
                AssertEx.Equal(
                    TimeSpan.FromSeconds(35),
                    defaults.For(EngineProtocol.Operations.Start),
                    "start operation");
                AssertEx.Equal(
                    TimeSpan.FromSeconds(25),
                    defaults.For(EngineProtocol.Operations.Stop),
                    "stop operation");
                AssertEx.Equal(
                    TimeSpan.FromSeconds(5),
                    defaults.For(EngineProtocol.Operations.Hello),
                    "hello operation");
                AssertEx.Equal(
                    TimeSpan.FromSeconds(5),
                    defaults.For(EngineProtocol.Operations.Status),
                    "status operation");
                AssertEx.Equal(
                    TimeSpan.FromSeconds(5),
                    defaults.For(EngineProtocol.Operations.Shutdown),
                    "shutdown operation");
                AssertEx.True(
                    defaults.StartBudget > defaults.StopBudget,
                    "start is the longest budget");
                AssertEx.True(
                    defaults.StopBudget > defaults.ShortBudget,
                    "stop is longer than a short budget");

                EngineServiceCallBudgets uniform =
                    EngineServiceCallBudgets.Uniform(TimeSpan.FromMilliseconds(700));
                AssertEx.Equal(
                    TimeSpan.FromMilliseconds(700),
                    uniform.For(EngineProtocol.Operations.Start),
                    "uniform start");
                AssertEx.Equal(
                    TimeSpan.FromMilliseconds(700),
                    uniform.For(EngineProtocol.Operations.Hello),
                    "uniform hello");

                bool zeroRefused = false;
                try
                {
                    EngineServiceCallBudgets.Uniform(TimeSpan.Zero);
                }
                catch (ArgumentOutOfRangeException)
                {
                    zeroRefused = true;
                }
                AssertEx.True(zeroRefused, "a zero budget is refused");

                EngineServiceCallBudgets custom = EngineServiceCallBudgets.Create(
                    TimeSpan.FromMilliseconds(100),
                    TimeSpan.FromMilliseconds(1200),
                    TimeSpan.FromMilliseconds(800));
                AssertEx.Equal(
                    TimeSpan.FromMilliseconds(1200),
                    custom.For(EngineProtocol.Operations.Start),
                    "custom start");
                AssertEx.Equal(
                    TimeSpan.FromMilliseconds(800),
                    custom.For(EngineProtocol.Operations.Stop),
                    "custom stop");
                AssertEx.Equal(
                    TimeSpan.FromMilliseconds(100),
                    custom.For(EngineProtocol.Operations.Status),
                    "custom short");

                bool customRefused = false;
                try
                {
                    EngineServiceCallBudgets.Create(
                        TimeSpan.FromMilliseconds(100),
                        TimeSpan.Zero,
                        TimeSpan.FromMilliseconds(800));
                }
                catch (ArgumentOutOfRangeException)
                {
                    customRefused = true;
                }
                AssertEx.True(customRefused, "a zero custom start budget is refused");
            });

            runner.Check("service client: the per-operation budget reaches the channel", delegate
            {
                BudgetChannel channel = new BudgetChannel();
                channel.Answers.Enqueue(SuccessAnswer(RunningStatusFields(Now())));
                channel.Answers.Enqueue(SuccessAnswer(RunningStatusFields(Now())));
                EngineServiceClient client = new EngineServiceClient(
                    channel,
                    EngineServiceCallBudgets.Default);

                Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Hello, Session, false),
                    CancellationToken.None));
                Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Status, Session, false),
                    CancellationToken.None));
                Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Start, Session, true),
                    CancellationToken.None));

                AssertEx.Equal(3, channel.Budgets.Count, "three exchanges");
                AssertEx.Equal(
                    TimeSpan.FromSeconds(5),
                    channel.Budgets[0],
                    "hello budget");
                AssertEx.Equal(
                    TimeSpan.FromSeconds(5),
                    channel.Budgets[1],
                    "status budget");
                AssertEx.Equal(
                    TimeSpan.FromSeconds(35),
                    channel.Budgets[2],
                    "start budget");
            });

            runner.Check("service client: an ambiguous answer is an unknown outcome, not a refusal", delegate
            {
                BudgetChannel channel = new BudgetChannel();
                channel.Answers.Enqueue(EngineServiceChannelAnswer.Ambiguous(
                    EngineProtocol.ErrorCodes.Timeout,
                    EngineServiceReplyReadProof.Partial));
                EngineServiceClient client = new EngineServiceClient(
                    channel,
                    EngineServiceCallBudgets.Default);
                EngineReply reply = Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Start, Session, true),
                    CancellationToken.None));
                AssertEx.False(reply.Ok, "not a success");
                AssertEx.True(reply.OutcomeUnknown, "the request may have been applied");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Timeout, reply.Code, "code");
                AssertEx.Equal("0", reply.Fields[EngineProtocol.Keys.Ok], "reply still a failure");

                BudgetChannel writeFailed = new BudgetChannel();
                writeFailed.Answers.Enqueue(EngineServiceChannelAnswer.WriteFailed(
                    EngineProtocol.ErrorCodes.EngineUnavailable,
                    true));
                EngineServiceClient writeFailedClient = new EngineServiceClient(
                    writeFailed,
                    EngineServiceCallBudgets.Default);
                EngineReply writeFailedReply = Wait(writeFailedClient.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Start, Session, true),
                    CancellationToken.None));
                AssertEx.False(writeFailedReply.Ok, "write failure");
                AssertEx.True(writeFailedReply.OutcomeUnknown, "a partial write is ambiguous");

                BudgetChannel notWritten = new BudgetChannel();
                notWritten.Answers.Enqueue(EngineServiceChannelAnswer.Failure(
                    EngineProtocol.ErrorCodes.Busy,
                    true));
                EngineServiceClient notWrittenClient = new EngineServiceClient(
                    notWritten,
                    EngineServiceCallBudgets.Default);
                EngineReply notWrittenReply = Wait(notWrittenClient.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Status, Session, false),
                    CancellationToken.None));
                AssertEx.False(notWrittenReply.Ok, "busy");
                AssertEx.False(notWrittenReply.OutcomeUnknown, "a busy gate delivered nothing");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Busy, notWrittenReply.Code, "busy code");

                BudgetChannel missingAnswer = new BudgetChannel();
                missingAnswer.ReturnNull = true;
                EngineServiceClient missingClient = new EngineServiceClient(
                    missingAnswer,
                    EngineServiceCallBudgets.Default);
                EngineReply missingReply = Wait(missingClient.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Stop, Session, false),
                    CancellationToken.None));
                AssertEx.False(missingReply.Ok, "a null answer is not a success");
                AssertEx.True(missingReply.OutcomeUnknown, "a null answer proves nothing");
            });

            runner.Check("service client: an unvalidated reply is an unknown outcome", delegate
            {
                BudgetChannel malformed = new BudgetChannel();
                malformed.Answers.Enqueue(EngineServiceChannelAnswer.Success(
                    new byte[] { 0, 0, 0, 2, 0xC3, 0x28 }));
                EngineServiceClient malformedClient = new EngineServiceClient(
                    malformed,
                    EngineServiceCallBudgets.Default);
                EngineReply malformedReply = Wait(malformedClient.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Start, Session, true),
                    CancellationToken.None));
                AssertEx.False(malformedReply.Ok, "malformed reply");
                AssertEx.True(
                    malformedReply.OutcomeUnknown,
                    "an invalid reply does not prove the start did not run");

                BudgetChannel failure = new BudgetChannel();
                Dictionary<string, string> failureFields = new Dictionary<string, string>(StringComparer.Ordinal);
                failureFields[EngineProtocol.Keys.Version] = "1";
                failureFields[EngineProtocol.Keys.Ok] = "0";
                failureFields[EngineProtocol.Keys.Code] = EngineProtocol.ErrorCodes.ManualPhone;
                failure.Answers.Enqueue(SuccessAnswer(failureFields));
                EngineServiceClient failureClient = new EngineServiceClient(
                    failure,
                    EngineServiceCallBudgets.Default);
                EngineReply failureReply = Wait(failureClient.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Start, Session, true),
                    CancellationToken.None));
                AssertEx.False(failureReply.Ok, "a failure reply");
                AssertEx.False(
                    failureReply.OutcomeUnknown,
                    "a validated failure reply is a clean refusal");
                AssertEx.Equal(
                    EngineProtocol.ErrorCodes.ManualPhone,
                    failureReply.Code,
                    "failure code");
            });

            runner.Check("service client: ambiguity belongs to one exchange", delegate
            {
                BudgetChannel channel = new BudgetChannel();
                channel.Answers.Enqueue(EngineServiceChannelAnswer.Ambiguous(
                    EngineProtocol.ErrorCodes.Timeout,
                    EngineServiceReplyReadProof.Unproven));
                channel.Answers.Enqueue(SuccessAnswer(RunningStatusFields(Now())));
                EngineServiceClient client = new EngineServiceClient(
                    channel,
                    EngineServiceCallBudgets.Default);

                EngineReply first = Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Status, Session, false),
                    CancellationToken.None));
                AssertEx.True(first.OutcomeUnknown, "first is ambiguous");

                EngineReply second = Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Status, Session, false),
                    CancellationToken.None));
                AssertEx.True(second.Ok, "second succeeds");
                AssertEx.False(second.OutcomeUnknown, "a later success is not ambiguous");
            });

            runner.Check("service client: a throwing exchange channel is an unknown outcome", delegate
            {
                // The frame was handed to an exchange channel. A throw does not
                // prove that no byte reached the service, so it is never a
                // clean refusal. A channel without outcome evidence keeps the
                // old fixed timeout, covered above.
                BudgetChannel channel = new BudgetChannel();
                channel.ThrowCanceled = true;
                EngineServiceClient client = new EngineServiceClient(
                    channel,
                    EngineServiceCallBudgets.Default);
                EngineReply reply = Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Status, Session, false),
                    CancellationToken.None));
                AssertEx.False(reply.Ok, "failure");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Timeout, reply.Code, "timeout code");
                AssertEx.True(
                    reply.OutcomeUnknown,
                    "an exchange channel that throws may have delivered the request");
            });

            runner.Check("service session: hello binds one session and launches nothing", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(ReadyStatus(now, now));
                SessionClock clock = new SessionClock(now);
                EngineServiceSession session = new EngineServiceSession("service-0001", backend, clock);

                EngineReply hello = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));

                AssertEx.True(hello.Ok, "hello");
                AssertEx.Equal(0, backend.Starts, "hello did not start");
                AssertEx.Equal(Session, session.BoundSessionId, "bound");
                AssertEx.Equal(EngineServiceSessionState.Active, session.State, "active");

                EngineReply status = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Status, Session),
                    CancellationToken.None));
                AssertEx.True(status.Ok, "status");
                EngineServiceStatus parsed;
                string code;
                AssertEx.True(
                    EngineServiceStatus.TryParse(status.Fields, clock.Now, out parsed, out code),
                    "status parse: " + code);
                AssertEx.False(parsed.Paired, "new session is not phase-one paired");
                AssertEx.Equal(EngineServicePairedScope.None, parsed.PairedScope, "new session scope");
                AssertEx.Equal(0, backend.Starts, "status did not start");
            });

            runner.Check("service session: status before hello and a second session are refused", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(ReadyStatus(now, now));
                SessionClock clock = new SessionClock(now);
                EngineServiceSession session = new EngineServiceSession("service-0001", backend, clock);

                EngineReply early = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Status, Session),
                    CancellationToken.None));
                AssertEx.False(early.Ok, "early status");
                AssertEx.Equal(EngineProtocol.ErrorCodes.NotConnected, early.Code, "early code");

                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                EngineReply second = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Status,
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                    CancellationToken.None));
                AssertEx.False(second.Ok, "second session");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Forbidden, second.Code, "second code");

                EngineReply foreignHello = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello,
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), CancellationToken.None));
                AssertEx.Equal(EngineProtocol.ErrorCodes.Forbidden, foreignHello.Code, "foreign hello");
                AssertEx.True(Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session), CancellationToken.None)).Ok,
                    "same session hello is repeatable");
                AssertEx.Equal(0, backend.Starts, "repeated hello never starts");
                backend.Status = null;
                EngineReply failedRepeat = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session), CancellationToken.None));
                AssertEx.False(failedRepeat.Ok, "active session hello can fail");
                AssertEx.Equal(Session, session.BoundSessionId, "failed repeat retains binding");
                AssertEx.Equal(EngineServiceSessionState.Active, session.State, "failed repeat stays active");
            });

            runner.Check("service session: concurrent hellos bind exactly one session", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(ReadyStatus(now, now));
                EngineServiceSession session = new EngineServiceSession("service-0001", backend, new SessionClock(now));
                string other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
                Task<EngineReply> first = Task.Run(() => session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session), CancellationToken.None));
                Task<EngineReply> second = Task.Run(() => session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, other), CancellationToken.None));
                AssertEx.True(Task.WaitAll(new Task[] { first, second }, TimeSpan.FromSeconds(5)), "hellos finish");
                AssertEx.True(first.Result.Ok != second.Result.Ok, "exactly one hello succeeds");
                EngineReply rejected = first.Result.Ok ? second.Result : first.Result;
                AssertEx.Equal(EngineProtocol.ErrorCodes.Forbidden, rejected.Code, "other hello refused");
                AssertEx.Equal(first.Result.Ok ? Session : other, session.BoundSessionId, "winner stays bound");
                AssertEx.Equal(0, backend.Starts, "hello never starts");
            });

            runner.Check("service session: failed hello stays unbound until a successful retry", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(null);
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001", backend, new SessionClock(now), ReadyGate(now));
                session.SetCredentialHeld(true);

                EngineReply failed = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session), CancellationToken.None));
                AssertEx.False(failed.Ok, "hello fails without backend status");
                AssertEx.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, failed.Code, "hello error");
                AssertEx.Equal(EngineServiceSessionState.NoSession, session.State, "still unbound");
                AssertEx.True(session.BoundSessionId == null, "no session id");

                backend.Status = ReadyStatus(now, now);
                EngineReply early = Wait(session.HandleAsync(StartFields(false), CancellationToken.None));
                AssertEx.False(early.Ok, "start before successful hello refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.NotConnected, early.Code, "start error");
                AssertEx.Equal(0, backend.Starts, "backend was not started");

                EngineReply retry = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session), CancellationToken.None));
                AssertEx.True(retry.Ok, "hello retry succeeds");
                AssertEx.Equal(Session, session.BoundSessionId, "retry binds session");
                EngineReply start = Wait(session.HandleAsync(StartFields(false), CancellationToken.None));
                AssertEx.True(start.Ok, "start after successful hello");
                AssertEx.Equal(1, backend.Starts, "backend started once");
            });

            runner.Check("service session: a start needs a credential, a source, and a fresh ready status", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(ReadyStatus(now, now));
                SessionClock clock = new SessionClock(now);
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001",
                    backend,
                    clock,
                    ReadyGate(now));
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));

                EngineReply noCredential = Wait(session.HandleAsync(
                    StartFields(true),
                    CancellationToken.None));
                AssertEx.False(noCredential.Ok, "no credential");
                AssertEx.Equal(EngineProtocol.ErrorCodes.ManualPhone, noCredential.Code, "credential code");
                AssertEx.Equal(0, backend.Starts, "no start");

                session.SetCredentialHeld(true);
                backend.Status = ReadyStatus(now, now);
                EngineReply ok = Wait(session.HandleAsync(StartFields(true), CancellationToken.None));
                AssertEx.True(ok.Ok, "start accepted");
                AssertEx.Equal(1, backend.Starts, "one start");
                AssertEx.True(backend.LastPing, "ping passed");
                AssertEx.Equal(2, ok.Fields.Count, "a start acknowledgement is not a status");

                backend.Status = NoSourceStatus(now);
                EngineReply noSource = Wait(session.HandleAsync(StartFields(false), CancellationToken.None));
                AssertEx.False(noSource.Ok, "no source");
                AssertEx.Equal(EngineProtocol.ErrorCodes.SourceMissing, noSource.Code, "source code");
                AssertEx.Equal(1, backend.Starts, "no second start");

                backend.Status = StaleReadyStatus(now);
                EngineReply stale = Wait(session.HandleAsync(StartFields(false), CancellationToken.None));
                AssertEx.False(stale.Ok, "stale");
                AssertEx.Equal(EngineProtocol.ErrorCodes.StaleStatus, stale.Code, "stale code");
                AssertEx.Equal(1, backend.Starts, "no stale start");
            });

            runner.Check("service session: a running tunnel, a cleanup latch, and a non-ready engine are refused", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(RunningStatus(now));
                SessionClock clock = new SessionClock(now);
                EngineServiceSession session = new EngineServiceSession("service-0001", backend, clock);
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));

                EngineReply running = Wait(session.HandleAsync(StartFields(false), CancellationToken.None));
                AssertEx.False(running.Ok, "running");
                AssertEx.Equal(EngineProtocol.ErrorCodes.AlreadyRunning, running.Code, "running code");

                backend.Status = CleanupFailedStatus(now);
                EngineReply blocked = Wait(session.HandleAsync(StartFields(false), CancellationToken.None));
                AssertEx.False(blocked.Ok, "cleanup");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupBlocked, blocked.Code, "cleanup code");

                backend.Status = UnavailableStatus(now);
                EngineReply unavailable = Wait(session.HandleAsync(StartFields(false), CancellationToken.None));
                AssertEx.False(unavailable.Ok, "unavailable");
                AssertEx.Equal(EngineProtocol.ErrorCodes.EngineUnavailable, unavailable.Code, "unavailable code");
                AssertEx.Equal(0, backend.Starts, "no start");
            });

            runner.Check("service session: stop, forget, parent loss, logoff, and shutdown are explicit", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(RunningStatus(now));
                SessionClock clock = new SessionClock(now);
                EngineServiceSession session = new EngineServiceSession("service-0001", backend, clock);
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));

                EngineReply forget = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Forget, Session),
                    CancellationToken.None));
                AssertEx.False(forget.Ok, "forget while running");
                AssertEx.Equal(EngineProtocol.ErrorCodes.ForgetWhileRunning, forget.Code, "forget code");

                EngineReply stop = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.True(stop.Ok, "stop");
                AssertEx.Equal(1, backend.Stops, "one stop");
                AssertEx.Equal(EngineServiceStopReason.User, backend.LastStop, "user reason");
                AssertEx.Equal(EngineServiceStopReason.User, session.LastStop, "session reason");
                AssertEx.False(session.CredentialHeld, "credential cleared");
                AssertEx.Equal(EngineServiceSessionState.Stopped, session.State, "stopped");

                EngineServiceSession lost = new EngineServiceSession(
                    "service-0002", new FakeBackend(RunningStatus(now)), new SessionClock(now));
                lost.SetCredentialHeld(true);
                Wait(lost.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                EngineServiceResult parent = lost.ParentLost();
                AssertEx.True(parent.Ok, "parent loss");
                AssertEx.Equal(EngineServiceStopReason.ParentLost, lost.LastStop, "parent reason");
                AssertEx.True(lost.IsClosed, "closed");
                AssertEx.False(lost.CredentialHeld, "cleared");
                EngineReply afterLoss = Wait(lost.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Status, Session),
                    CancellationToken.None));
                AssertEx.Equal(EngineProtocol.ErrorCodes.Closed, afterLoss.Code, "closed code");

                FakeBackend shutdownBackend = new FakeBackend(RunningStatus(now));
                EngineServiceSession shutdown = new EngineServiceSession(
                    "service-0001", shutdownBackend, new SessionClock(now));
                shutdown.SetCredentialHeld(true);
                Wait(shutdown.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                EngineReply shutdownReply = Wait(shutdown.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Shutdown, Session),
                    CancellationToken.None));
                AssertEx.True(shutdownReply.Ok, "shutdown");
                AssertEx.Equal(EngineServiceStopReason.ServiceStop, shutdownBackend.LastStop, "service stop reason");
                AssertEx.True(shutdown.IsClosed, "shutdown closed");

                FakeBackend logoffBackend = new FakeBackend(RunningStatus(now));
                EngineServiceSession logoff = new EngineServiceSession(
                    "service-0004", logoffBackend, new SessionClock(now));
                logoff.SetCredentialHeld(true);
                Wait(logoff.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                EngineServiceResult logoffResult = logoff.ServiceStopped(
                    EngineServiceStopReason.SessionLogoff);
                AssertEx.True(logoffResult.Ok, "logoff");
                AssertEx.Equal(EngineServiceStopReason.SessionLogoff, logoffBackend.LastStop, "logoff reason");
                AssertEx.True(logoff.IsClosed, "logoff closed");
            });

            runner.Check("service session: a lost session never restarts the engine", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(RunningStatus(now));
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001", backend, new SessionClock(now));
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                session.ParentLost();
                AssertEx.Equal(0, backend.Starts, "no start");
                AssertEx.Equal(1, backend.Stops, "one stop");
                EngineReply late = Wait(session.HandleAsync(StartFields(true), CancellationToken.None));
                AssertEx.False(late.Ok, "late start");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Closed, late.Code, "closed code");
                AssertEx.Equal(0, backend.Starts, "still no start");
            });

            runner.Check("service session: a stop runs even when the status is unavailable", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend parentBackend = new FakeBackend(null);
                EngineServiceSession parent = new EngineServiceSession(
                    "service-0001", parentBackend, new SessionClock(now));
                parent.SetCredentialHeld(true);
                EngineReply parentHello = Wait(parent.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                AssertEx.False(parentHello.Ok, "hello failed before parent loss");
                AssertEx.True(parent.BoundSessionId == null, "failed hello did not bind");
                EngineServiceResult parentResult = parent.ParentLost();
                AssertEx.True(parentResult.Ok, "parent stop");
                AssertEx.Equal(1, parentBackend.Stops, "parent stop called");
                AssertEx.Equal(EngineServiceStopReason.ParentLost, parentBackend.LastStop, "parent reason");
                AssertEx.True(parent.IsClosed, "parent closed");

                FakeBackend serviceBackend = new FakeBackend(null);
                EngineServiceSession service = new EngineServiceSession(
                    "service-0001", serviceBackend, new SessionClock(now));
                AssertEx.False(Wait(service.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session), CancellationToken.None)).Ok,
                    "hello failed before service stop");
                AssertEx.True(service.ServiceStopped(EngineServiceStopReason.ServiceStop).Ok, "service stop");
                AssertEx.Equal(1, serviceBackend.Stops, "service stop called once");
                AssertEx.True(service.IsClosed, "service closed");

                FakeBackend shutdownBackend = new FakeBackend(RunningStatus(now));
                EngineServiceSession shutdown = new EngineServiceSession(
                    "service-0001", shutdownBackend, new SessionClock(now));
                shutdown.SetCredentialHeld(true);
                AssertEx.True(Wait(shutdown.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None)).Ok, "hello before status loss");
                shutdownBackend.Status = null;
                EngineReply shutdownReply = Wait(shutdown.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Shutdown, Session),
                    CancellationToken.None));
                AssertEx.True(shutdownReply.Ok, "shutdown stop");
                AssertEx.Equal(1, shutdownBackend.Stops, "shutdown stop called");
                AssertEx.Equal(EngineServiceStopReason.ServiceStop, shutdownBackend.LastStop, "shutdown reason");
                AssertEx.True(shutdown.IsClosed, "shutdown closed");
            });

            runner.Check("service session: a start without a readable durable record fails closed", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(ReadyStatus(now, now));
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001", backend, new SessionClock(now));
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                AssertEx.False(session.StateGate.HasRecord, "no durable record");

                EngineReply start = Wait(session.HandleAsync(StartFields(false), CancellationToken.None));
                AssertEx.False(start.Ok, "start refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, start.Code, "unknown code");
                AssertEx.Equal(0, backend.Starts, "no process launched");
            });

            runner.Check("service session: a status from another service instance is refused", delegate
            {
                DateTimeOffset now = Now();
                Dictionary<string, string> fields = ReadyStatusFields(now);
                fields[EngineServiceStatusKeys.Instance] = "service-0002";
                EngineServiceStatus other = ParseStatus(fields, now);
                FakeBackend backend = new FakeBackend(other);
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001",
                    backend,
                    new SessionClock(now),
                    ReadyGate(now));
                session.SetCredentialHeld(true);

                EngineReply hello = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                AssertEx.False(hello.Ok, "hello refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.EngineRestarted, hello.Code, "hello code");

                EngineReply status = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Status, Session),
                    CancellationToken.None));
                AssertEx.False(status.Ok, "status refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.NotConnected, status.Code, "status code");

                EngineReply start = Wait(session.HandleAsync(StartFields(false), CancellationToken.None));
                AssertEx.False(start.Ok, "start refused");
                AssertEx.Equal(EngineProtocol.ErrorCodes.NotConnected, start.Code, "start code");
                AssertEx.Equal(0, backend.Starts, "no process launched");
            });

            runner.Check("service session: an old source answer blocks a start read now", delegate
            {
                DateTimeOffset now = Now();
                Dictionary<string, string> fields = ReadyStatusFields(now);
                fields[EngineServiceStatusKeys.CheckedAt] =
                    now.AddSeconds(-20).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                EngineServiceStatus status = ParseStatus(fields, now);
                FakeBackend backend = new FakeBackend(status);
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001",
                    backend,
                    new SessionClock(now),
                    ReadyGate(now));
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));

                EngineReply start = Wait(session.HandleAsync(StartFields(false), CancellationToken.None));
                AssertEx.False(start.Ok, "stale source");
                AssertEx.Equal(EngineProtocol.ErrorCodes.StaleStatus, start.Code, "stale code");
                AssertEx.Equal(0, backend.Starts, "no process launched");
            });

            runner.Check("service session: a phase-one stop clears the pairing claim", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(ReadyStatus(now, now));
                SessionClock clock = new SessionClock(now);
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001",
                    backend,
                    clock,
                    ReadyGate(now));
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                AssertEx.False(session.PairingCleared, "paired before the stop");

                EngineReply stop = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.True(stop.Ok, "stop");
                AssertEx.True(session.PairingCleared, "cleared after the stop");

                EngineReply statusReply = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Status, Session),
                    CancellationToken.None));
                AssertEx.True(statusReply.Ok, "status after stop");
                EngineServiceStatus cleared;
                string code;
                AssertEx.True(
                    EngineServiceStatus.TryParse(statusReply.Fields, clock.Now, out cleared, out code),
                    "cleared status: " + code);
                AssertEx.False(cleared.Paired, "unpaired");
                AssertEx.Equal(EngineServicePairedScope.None, cleared.PairedScope, "scope");
                AssertEx.False(cleared.SourcePresent, "no source");
                AssertEx.False(cleared.TrustedBySource, "no trust");
                AssertEx.False(cleared.CheckedAt.HasValue, "no check time");
                AssertEx.False(cleared.PhoneConnections.HasValue, "no source count");
                AssertEx.False(cleared.RelayTcpFlowsActive.HasValue, "no relay count");

                Dictionary<string, string> identityFields = ReadyStatusFields(now);
                identityFields[EngineServiceStatusKeys.PairedScope] = "identity";
                identityFields[EngineServiceStatusKeys.Instance] = "service-0002";
                EngineServiceStatus identity = ParseStatus(identityFields, now);
                FakeBackend identityBackend = new FakeBackend(identity);
                EngineServiceSession identitySession = new EngineServiceSession(
                    "service-0002",
                    identityBackend,
                    clock,
                    ReadyGate(now));
                identitySession.SetCredentialHeld(true);
                Wait(identitySession.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                EngineReply identityStop = Wait(identitySession.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.True(identityStop.Ok, "identity stop");
                EngineReply identityStatus = Wait(identitySession.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Status, Session),
                    CancellationToken.None));
                AssertEx.True(identityStatus.Ok, "identity status");
                EngineServiceStatus kept;
                AssertEx.True(
                    EngineServiceStatus.TryParse(identityStatus.Fields, clock.Now, out kept, out code),
                    "kept status: " + code);
                AssertEx.True(kept.Paired, "identity pairing kept");
                AssertEx.Equal(EngineServicePairedScope.Identity, kept.PairedScope, "identity scope kept");
            });

            runner.Check("service session: concurrent requests serialize and a waiting request can cancel", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(ReadyStatus(now, now));
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001",
                    backend,
                    new SessionClock(now),
                    ReadyGate(now));
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));

                backend.BlockStart = true;
                Task<EngineReply> first = Task.Run(() => session.HandleAsync(
                    StartFields(false),
                    CancellationToken.None));
                AssertEx.True(backend.StartEntered.Wait(TimeSpan.FromSeconds(5)), "first start entered");

                CancellationTokenSource cancel = new CancellationTokenSource();
                Task<EngineReply> second = Task.Run(() => session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Status, Session),
                    cancel.Token));
                cancel.Cancel();
                AssertEx.True(second.Wait(TimeSpan.FromSeconds(5)), "second request did not finish");
                EngineReply secondReply = second.Result;
                AssertEx.False(secondReply.Ok, "waiting request cancelled");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Timeout, secondReply.Code, "timeout code");
                AssertEx.Equal(1, backend.MaxActiveCalls, "one backend call at a time");

                backend.ReleaseStart.Set();
                AssertEx.True(first.Wait(TimeSpan.FromSeconds(5)), "first request did not finish");
                EngineReply firstReply = first.Result;
                AssertEx.True(firstReply.Ok, "first start");
                AssertEx.Equal(1, backend.Starts, "one start");
                AssertEx.Equal(1, backend.MaxActiveCalls, "still one backend call at a time");
            });

            runner.Check("service session: a canceled start is cleanup unknown and can still be stopped", delegate
            {
                DateTimeOffset now = Now();
                CancellableFakeBackend backend = new CancellableFakeBackend(ReadyStatus(now, now));
                backend.BlockStart = true;
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001",
                    backend,
                    new SessionClock(now),
                    ReadyGate(now));
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));

                CancellationTokenSource cancel = new CancellationTokenSource();
                Task<EngineReply> start = Task.Run(() => session.HandleAsync(
                    StartFields(false),
                    cancel.Token));
                AssertEx.True(backend.StartEntered.Wait(TimeSpan.FromSeconds(5)), "start entered");
                cancel.Cancel();
                AssertEx.True(start.Wait(TimeSpan.FromSeconds(5)), "canceled start returns");
                EngineReply reply = start.Result;
                AssertEx.False(reply.Ok, "canceled start is not success");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, reply.Code, "cleanup unknown");
                AssertEx.Equal(1, backend.Starts, "one start attempt");

                EngineReply stop = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.True(stop.Ok, "stop after a canceled start");
                AssertEx.Equal(1, backend.Stops, "one cleanup stop");
            });

            runner.Check("service session: a canceled or timed-out stop is cleanup unknown, never success", delegate
            {
                DateTimeOffset now = Now();
                CancellableFakeBackend backend = new CancellableFakeBackend(ReadyStatus(now, now));
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001",
                    backend,
                    new SessionClock(now),
                    ReadyGate(now));
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                EngineReply start = Wait(session.HandleAsync(StartFields(false), CancellationToken.None));
                AssertEx.True(start.Ok, "start");
                AssertEx.Equal(1, backend.Starts, "one start");

                backend.BlockStop = true;
                CancellationTokenSource cancel = new CancellationTokenSource();
                Task<EngineReply> stop = Task.Run(() => session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    cancel.Token));
                AssertEx.True(backend.StopEntered.Wait(TimeSpan.FromSeconds(5)), "stop entered");
                cancel.Cancel();
                AssertEx.True(stop.Wait(TimeSpan.FromSeconds(5)), "canceled stop returns");
                EngineReply reply = stop.Result;
                AssertEx.False(reply.Ok, "canceled stop is not success");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, reply.Code, "cleanup unknown");
                AssertEx.Equal(1, backend.Stops, "one stop attempt");
                AssertEx.True(session.IsClosed, "a failed stop closes the session");

                EngineReply repeated = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.False(repeated.Ok, "a repeated stop is not success");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Closed, repeated.Code, "closed code");
                AssertEx.Equal(1, backend.Stops, "no second stop");

                CancellableFakeBackend timeoutBackend =
                    new CancellableFakeBackend(ReadyStatus(now, now));
                timeoutBackend.BlockStop = true;
                EngineServiceSession timeoutSession = new EngineServiceSession(
                    "service-0001",
                    timeoutBackend,
                    new SessionClock(now),
                    ReadyGate(now),
                    TimeSpan.FromMilliseconds(500));
                timeoutSession.SetCredentialHeld(true);
                Wait(timeoutSession.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                EngineReply timeoutStart = Wait(timeoutSession.HandleAsync(
                    StartFields(false),
                    CancellationToken.None));
                AssertEx.True(timeoutStart.Ok, "timeout start: " + timeoutStart.Code);
                EngineReply timeoutStop = Wait(timeoutSession.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.False(timeoutStop.Ok, "timed-out stop is not success");
                AssertEx.Equal(
                    EngineProtocol.ErrorCodes.CleanupUnknown,
                    timeoutStop.Code,
                    "timed-out stop code");
                AssertEx.True(timeoutSession.IsClosed, "timed-out stop closes");
                AssertEx.Equal(1, timeoutBackend.Stops, "timeout stop attempt");
            });

            runner.Check("service session: a backend timeout result is cleanup unknown", delegate
            {
                DateTimeOffset now = Now();
                CancellableFakeBackend startBackend =
                    new CancellableFakeBackend(ReadyStatus(now, now));
                startBackend.StartCode = EngineProtocol.ErrorCodes.Timeout;
                EngineServiceSession startSession = new EngineServiceSession(
                    "service-0001",
                    startBackend,
                    new SessionClock(now),
                    ReadyGate(now));
                startSession.SetCredentialHeld(true);
                Wait(startSession.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                EngineReply start = Wait(startSession.HandleAsync(
                    StartFields(false),
                    CancellationToken.None));
                AssertEx.False(start.Ok, "timeout start is not success");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, start.Code, "start code");

                CancellableFakeBackend stopBackend =
                    new CancellableFakeBackend(ReadyStatus(now, now));
                EngineServiceSession stopSession = new EngineServiceSession(
                    "service-0001",
                    stopBackend,
                    new SessionClock(now),
                    ReadyGate(now));
                stopSession.SetCredentialHeld(true);
                Wait(stopSession.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                AssertEx.True(Wait(stopSession.HandleAsync(
                    StartFields(false),
                    CancellationToken.None)).Ok, "stop session start");
                stopBackend.StopCode = EngineProtocol.ErrorCodes.Timeout;
                EngineReply stop = Wait(stopSession.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.False(stop.Ok, "timeout stop is not success");
                AssertEx.Equal(EngineProtocol.ErrorCodes.CleanupUnknown, stop.Code, "stop code");
                AssertEx.True(stopSession.IsClosed, "timeout stop closes");
            });

            runner.Check("service session: every stop trigger runs one backend stop", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(RunningStatus(now));
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001",
                    backend,
                    new SessionClock(now),
                    ReadyGate(now));
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));

                EngineReply first = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.True(first.Ok, "first stop");
                EngineReply second = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.True(second.Ok, "second stop is idempotent");
                AssertEx.Equal(1, backend.Stops, "one user stop");
                AssertEx.Equal(EngineServiceStopReason.User, backend.LastStop, "user reason");

                EngineServiceResult parent = session.ParentLost();
                AssertEx.True(parent.Ok, "parent close");
                AssertEx.Equal(1, backend.Stops, "parent did not stop twice");
                AssertEx.Equal(EngineServiceStopReason.User, session.LastStop, "first reason kept");
                AssertEx.True(session.IsClosed, "closed");

                FakeBackend failedBackend = new FakeBackend(RunningStatus(now));
                failedBackend.StopOk = false;
                EngineServiceSession failed = new EngineServiceSession(
                    "service-0001",
                    failedBackend,
                    new SessionClock(now),
                    ReadyGate(now));
                failed.SetCredentialHeld(true);
                Wait(failed.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                EngineReply failedFirst = Wait(failed.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.False(failedFirst.Ok, "failed stop");
                AssertEx.Equal(EngineProtocol.ErrorCodes.EngineStopTimeout, failedFirst.Code, "failed code");
                EngineReply failedSecond = Wait(failed.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.False(failedSecond.Ok, "closed after failed stop");
                AssertEx.Equal(EngineProtocol.ErrorCodes.Closed, failedSecond.Code, "closed code");
                AssertEx.Equal(1, failedBackend.Stops, "one backend stop on failure");
                AssertEx.False(failed.CredentialHeld, "credential cleared");
                AssertEx.True(failed.PairingCleared, "pairing cleared");
                AssertEx.True(failed.IsClosed, "failed stop closes the session");

                FakeBackend concurrentBackend = new FakeBackend(RunningStatus(now));
                EngineServiceSession concurrent = new EngineServiceSession(
                    "service-0003",
                    concurrentBackend,
                    new SessionClock(now),
                    ReadyGate(now));
                concurrent.SetCredentialHeld(true);
                Wait(concurrent.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));
                Task<EngineServiceResult> parentTask = Task.Run(() => concurrent.ParentLost());
                Task<EngineServiceResult> serviceTask = Task.Run(
                    () => concurrent.ServiceStopped(EngineServiceStopReason.ServiceStop));
                AssertEx.True(
                    Task.WaitAll(
                        new Task[] { parentTask, serviceTask },
                        TimeSpan.FromSeconds(5)),
                    "concurrent stops finished");
                AssertEx.True(parentTask.Result.Ok, "parent result");
                AssertEx.True(serviceTask.Result.Ok, "service result");
                AssertEx.Equal(1, concurrentBackend.Stops, "one concurrent stop");
                AssertEx.True(concurrent.IsClosed, "concurrent closed");
                AssertEx.True(
                    concurrentBackend.LastStop == EngineServiceStopReason.ParentLost
                        || concurrentBackend.LastStop == EngineServiceStopReason.ServiceStop,
                    "first close reason");
            });

            runner.Check("service session: a clean stop can be followed by a new start and a new stop", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(ReadyStatus(now, now));
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001",
                    backend,
                    new SessionClock(now),
                    ReadyGate(now));
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));

                EngineReply firstStart = Wait(session.HandleAsync(
                    StartFields(false),
                    CancellationToken.None));
                AssertEx.True(firstStart.Ok, "first start");
                AssertEx.Equal(1, backend.Starts, "one start");
                EngineReply firstStop = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.True(firstStop.Ok, "first stop");
                AssertEx.Equal(1, backend.Stops, "one stop");

                session.SetCredentialHeld(true);
                EngineReply secondStart = Wait(session.HandleAsync(
                    StartFields(false),
                    CancellationToken.None));
                AssertEx.True(secondStart.Ok, "second start");
                AssertEx.Equal(2, backend.Starts, "second start called");
                EngineReply secondStop = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.True(secondStop.Ok, "second stop");
                AssertEx.Equal(2, backend.Stops, "second stop called");
                AssertEx.Equal(EngineServiceStopReason.User, session.LastStop, "new stop reason");
            });

            runner.Check("service session: a failed start after a clean stop can still be stopped", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(ReadyStatus(now, now));
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001",
                    backend,
                    new SessionClock(now),
                    ReadyGate(now));
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));

                EngineReply firstStart = Wait(session.HandleAsync(
                    StartFields(false),
                    CancellationToken.None));
                AssertEx.True(firstStart.Ok, "first start");
                EngineReply firstStop = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.True(firstStop.Ok, "first stop");
                AssertEx.Equal(1, backend.Stops, "one stop");

                session.SetCredentialHeld(true);
                backend.StartOk = false;
                EngineReply failedStart = Wait(session.HandleAsync(
                    StartFields(false),
                    CancellationToken.None));
                AssertEx.False(failedStart.Ok, "second start failed");
                AssertEx.Equal(EngineProtocol.ErrorCodes.RouteSetup, failedStart.Code, "start code");
                AssertEx.Equal(2, backend.Starts, "second start attempted");
                AssertEx.Equal(1, backend.Stops, "no stop before the request");

                EngineReply secondStop = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.True(secondStop.Ok, "stop after failed start");
                AssertEx.Equal(2, backend.Stops, "the failed attempt is stopped once");
                AssertEx.Equal(EngineServiceStopReason.User, session.LastStop, "stop reason");
            });

            runner.Check("service session: a repeated stop clears a newly held credential without a second backend stop", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(ReadyStatus(now, now));
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001",
                    backend,
                    new SessionClock(now),
                    ReadyGate(now));
                session.SetCredentialHeld(true);
                Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Hello, Session),
                    CancellationToken.None));

                EngineReply firstStop = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.True(firstStop.Ok, "first stop");
                AssertEx.Equal(1, backend.Stops, "one backend stop");

                session.SetCredentialHeld(true);
                AssertEx.True(session.CredentialHeld, "credential held again");
                EngineReply repeated = Wait(session.HandleAsync(
                    RequestFields(EngineProtocol.Operations.Stop, Session),
                    CancellationToken.None));
                AssertEx.True(repeated.Ok, "repeated stop");
                AssertEx.False(session.CredentialHeld, "credential cleared");
                AssertEx.True(session.PairingCleared, "pairing cleared");
                AssertEx.Equal(1, backend.Stops, "no second backend stop");
            });

            runner.Check("service loop: the client and the session share one frame contract", delegate
            {
                DateTimeOffset now = Now();
                FakeBackend backend = new FakeBackend(ReadyStatus(now, now));
                EngineServiceSession session = new EngineServiceSession(
                    "service-0001",
                    backend,
                    new SessionClock(now),
                    ReadyGate(now));
                LoopbackChannel channel = new LoopbackChannel(session);
                EngineServiceClient client = new EngineServiceClient(
                    channel,
                    TimeSpan.FromMilliseconds(500));

                EngineReply hello = Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Hello, Session, false),
                    CancellationToken.None));
                AssertEx.True(hello.Ok, "hello");
                AssertEx.Equal("service-0001", hello.Fields[EngineServiceStatusKeys.Instance], "instance");

                EngineReply status = Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Status, Session, false),
                    CancellationToken.None));
                AssertEx.True(status.Ok, "status");
                AssertEx.Equal(24, status.Fields.Count, "status field count");

                EngineReply noCredential = Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Start, Session, true),
                    CancellationToken.None));
                AssertEx.False(noCredential.Ok, "no credential");
                AssertEx.Equal(EngineProtocol.ErrorCodes.ManualPhone, noCredential.Code, "credential code");
                AssertEx.Equal(0, backend.Starts, "hello, status, and a refused start launched nothing");

                session.SetCredentialHeld(true);
                EngineReply started = Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Start, Session, true),
                    CancellationToken.None));
                AssertEx.True(started.Ok, "start");
                AssertEx.Equal(1, backend.Starts, "one start");
                AssertEx.True(backend.LastPing, "ping");

                EngineReply stopped = Wait(client.SendAsync(
                    new EngineRequest(EngineProtocol.Operations.Stop, Session, false),
                    CancellationToken.None));
                AssertEx.True(stopped.Ok, "stop");
                AssertEx.False(session.CredentialHeld, "credential cleared");
            });

            runner.Check("service contract: every new error code has fixed text", delegate
            {
                string[] codes =
                {
                    EngineProtocol.ErrorCodes.BoundaryAuthFailed,
                    EngineProtocol.ErrorCodes.BoundaryBusy,
                    EngineProtocol.ErrorCodes.CleanupBlocked,
                    EngineProtocol.ErrorCodes.CleanupUnknown,
                    EngineProtocol.ErrorCodes.CleanupPending,
                    EngineProtocol.ErrorCodes.AdminRequired,
                    EngineProtocol.ErrorCodes.ManualPhone,
                    EngineProtocol.ErrorCodes.RouteSetup,
                    EngineProtocol.ErrorCodes.TunnelSetup,
                    EngineProtocol.ErrorCodes.ProtocolMismatch,
                    EngineProtocol.ErrorCodes.LaunchTimeout,
                    EngineProtocol.ErrorCodes.EngineStopTimeout,
                    EngineProtocol.ErrorCodes.EngineLost,
                    EngineProtocol.ErrorCodes.SourceDeviceGone,
                    EngineProtocol.ErrorCodes.ObservationUnavailable,
                    EngineProtocol.ErrorCodes.GatewayChanged,
                    EngineProtocol.ErrorCodes.LinkChanged,
                    EngineProtocol.ErrorCodes.LinkUnknown,
                    EngineProtocol.ErrorCodes.ServiceStop,
                    EngineProtocol.ErrorCodes.Shutdown,
                    EngineProtocol.ErrorCodes.SessionLogoff,
                    EngineProtocol.ErrorCodes.Starting
                };
                for (int index = 0; index < codes.Length; index++)
                {
                    AssertEx.True(EngineProtocol.IsKnownErrorCode(codes[index]), codes[index] + " is known");
                    AssertEx.NotEmpty(EngineProtocol.ErrorText(codes[index]), codes[index] + " text");
                    EngineReply reply = EngineReply.Failure(codes[index]);
                    AssertEx.Equal(codes[index], reply.Code, codes[index] + " reply");
                }
            });

            // The owner decision of 2026-11-06 enables Windows token use
            // behind the read-only physical adapter and default gateway
            // check. The gate must stay in place at every token use.
            runner.Check("service contract: the engine token gate is present and not bypassed", delegate
            {
                string root = FindRepoRoot();
                AssertEx.True(root != null, "repo root");
                string guard = File.ReadAllText(Path.Combine(root, "rust", "src", "windows_route_verify.rs"));
                AssertEx.Contains(guard, "require_token_destination_proof", "gate function");
                AssertEx.Contains(guard, "observe_token_destination", "physical adapter and gateway observation");
                AssertEx.Contains(guard, "TOKEN_DESTINATION_REFUSED", "fixed refusal");
            });

            runner.Check("service contract: no service install, service start, or forced termination is in the tree", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                foreach (string file in Files(Path.Combine(root, "src"), "*.cs"))
                {
                    string text = File.ReadAllText(file);
                    AssertEx.DoesNotContain(text, "Create" + "Service", file);
                    // StartServiceCtrlDispatcherW is the reviewed SCM receive
                    // path. Every other StartService API remains forbidden.
                    AssertOnlyServiceDispatcherStart(text, file);
                    AssertEx.DoesNotContain(text, "Delete" + "Service", file);
                    AssertEx.DoesNotContain(text, "Change" + "Service" + "Config", file);
                    AssertEx.DoesNotContain(text, "Service" + "Controller", file);
                    AssertEx.DoesNotContain(text, "Terminate" + "Process", file);
                }
            });

            runner.Check("service contract: the app uses the broker and does not load the service foundation", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string app = Path.Combine(root, "src", "HotspotShade.WinUI2");
                foreach (string file in Directory.EnumerateFiles(app, "*.cs", SearchOption.AllDirectories))
                {
                    string text = File.ReadAllText(file);
                    AssertEx.DoesNotContain(text, "EngineServiceClient", file);
                    AssertEx.DoesNotContain(text, "EngineServiceBoundary", file);
                }
                string project = File.ReadAllText(Path.Combine(app, "HotspotShade.WinUI2.csproj"));
                AssertEx.DoesNotContain(project, "HotspotShade.WinUI2.ServiceHost", "no service host reference");
                AssertEx.DoesNotContain(project, "HotspotShade.WinUI2.Service.csproj", "no service reference");
            });

            runner.Check("service contract: the foundation docs state the limits and the gates", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows root");
                string doc = Path.Combine(root, "SERVICE_BOUNDARY.md");
                AssertEx.True(File.Exists(doc), "SERVICE_BOUNDARY.md");
                string text = File.ReadAllText(doc);
                AssertEx.Contains(text, "UNAPPROVED", "design status");
                AssertEx.Contains(text, "not production ready", "readiness");
                AssertEx.Contains(text, "G1", "G1");
                AssertEx.Contains(text, "G2", "G2");
                AssertEx.Contains(text, "not installed", "install limit");
                AssertEx.Contains(text, "no Windows host run", "host limit");
                AssertEx.Contains(text, "PIPE_REJECT_REMOTE_CLIENTS", "remote rejection");
                AssertEx.Contains(text, "FILE_FLAG_FIRST_PIPE_INSTANCE", "first instance");
                AssertEx.Contains(text, "exactly one instance", "one instance");
                AssertEx.Contains(text, "allowed, not blocked", "same-user allowed");
                AssertEx.Contains(text, "remote clients", "remote client rule");
                AssertEx.Contains(text, "Repaired review findings", "repair record");
                string readme = File.ReadAllText(Path.Combine(root, "README.md"));
                AssertEx.Contains(readme, "service boundary foundation", "README foundation");
            });
        }

        private const string Session = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // The only StartService spelling that may appear in this tree is the
        // SCM receive path, StartServiceCtrlDispatcherW. The install and start
        // APIs remain forbidden.
        private static void AssertOnlyServiceDispatcherStart(string text, string what)
        {
            string allowed = "Start" + "Service" + "Ctrl" + "DispatcherW";
            int index = text.IndexOf("Start" + "Service", StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                bool matches = index + allowed.Length <= text.Length
                    && string.Compare(
                        text,
                        index,
                        allowed,
                        0,
                        allowed.Length,
                        StringComparison.OrdinalIgnoreCase) == 0;
                AssertEx.True(
                    matches,
                    what + ": only StartServiceCtrlDispatcherW may appear");
                index = text.IndexOf(
                    "Start" + "Service",
                    index + 1,
                    StringComparison.OrdinalIgnoreCase);
            }
        }

        private static void AssertFrameRefused(string json, string what)        {
            byte[] frame = RawFrame(json);
            Dictionary<string, string> fields;
            string code;
            AssertEx.False(
                EngineServiceFrame.TryDecode(frame, frame.Length, out fields, out code),
                what);
        }

        private static void AssertStatusRefused(
            Dictionary<string, string> fields,
            DateTimeOffset now,
            string what)
        {
            EngineServiceStatus status;
            string code;
            AssertEx.False(EngineServiceStatus.TryParse(fields, now, out status, out code), what);
        }

        private static Dictionary<string, string> RequestFields(string operation, string session)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Version] = "1";
            fields[EngineProtocol.Keys.Operation] = operation;
            fields[EngineProtocol.Keys.Session] = session;
            return fields;
        }

        private static Dictionary<string, string> RunningStatusFields(DateTimeOffset now)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineServiceStatusKeys.Version] = "1";
            fields[EngineServiceStatusKeys.Ok] = "1";
            fields[EngineServiceStatusKeys.Instance] = "service-0001";
            fields[EngineServiceStatusKeys.Engine] = "running";
            fields[EngineServiceStatusKeys.Running] = "1";
            fields[EngineServiceStatusKeys.Mode] = "phone";
            fields[EngineServiceStatusKeys.Paired] = "1";
            fields[EngineServiceStatusKeys.PairedScope] = "identity";
            fields[EngineServiceStatusKeys.Source] = "1";
            fields[EngineServiceStatusKeys.Trusted] = "1";
            fields[EngineServiceStatusKeys.CheckedAt] =
                now.AddSeconds(-5).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            fields[EngineServiceStatusKeys.Ping] = "1";
            fields[EngineServiceStatusKeys.IcmpEnabled] = "1";
            fields[EngineServiceStatusKeys.PhoneConnections] = "3";
            fields[EngineServiceStatusKeys.PhoneConnectionsKnown] = "1";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActive] = "7";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActiveKnown] = "1";
            fields[EngineServiceStatusKeys.TtlBad] = "0";
            fields[EngineServiceStatusKeys.Ipv6Dropped] = "0";
            fields[EngineServiceStatusKeys.FragmentsDropped] = "0";
            fields[EngineServiceStatusKeys.Stop] = "none";
            fields[EngineServiceStatusKeys.StopAt] = "";
            fields[EngineServiceStatusKeys.Cleanup] = "unknown";
            fields[EngineServiceStatusKeys.Admin] = "1";
            return fields;
        }

        private static Dictionary<string, string> StoppedStatusFields(DateTimeOffset now)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineServiceStatusKeys.Version] = "1";
            fields[EngineServiceStatusKeys.Ok] = "1";
            fields[EngineServiceStatusKeys.Instance] = "service-0001";
            fields[EngineServiceStatusKeys.Engine] = "ready";
            fields[EngineServiceStatusKeys.Running] = "0";
            fields[EngineServiceStatusKeys.Mode] = "phone";
            fields[EngineServiceStatusKeys.Paired] = "0";
            fields[EngineServiceStatusKeys.PairedScope] = "none";
            fields[EngineServiceStatusKeys.Source] = "0";
            fields[EngineServiceStatusKeys.Trusted] = "0";
            fields[EngineServiceStatusKeys.CheckedAt] = "";
            fields[EngineServiceStatusKeys.Ping] = "0";
            fields[EngineServiceStatusKeys.IcmpEnabled] = "0";
            fields[EngineServiceStatusKeys.PhoneConnections] = "";
            fields[EngineServiceStatusKeys.PhoneConnectionsKnown] = "0";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActive] = "";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActiveKnown] = "0";
            fields[EngineServiceStatusKeys.TtlBad] = "0";
            fields[EngineServiceStatusKeys.Ipv6Dropped] = "0";
            fields[EngineServiceStatusKeys.FragmentsDropped] = "0";
            fields[EngineServiceStatusKeys.Stop] = "user";
            fields[EngineServiceStatusKeys.StopAt] =
                now.AddSeconds(-5).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            fields[EngineServiceStatusKeys.Cleanup] = "ok";
            fields[EngineServiceStatusKeys.Admin] = "1";
            return fields;
        }

        private static EngineServiceStatus ReadyStatus(DateTimeOffset now, DateTimeOffset observedAt)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineServiceStatusKeys.Version] = "1";
            fields[EngineServiceStatusKeys.Ok] = "1";
            fields[EngineServiceStatusKeys.Instance] = "service-0001";
            fields[EngineServiceStatusKeys.Engine] = "ready";
            fields[EngineServiceStatusKeys.Running] = "0";
            fields[EngineServiceStatusKeys.Mode] = "phone";
            fields[EngineServiceStatusKeys.Paired] = "1";
            fields[EngineServiceStatusKeys.PairedScope] = "session";
            fields[EngineServiceStatusKeys.Source] = "1";
            fields[EngineServiceStatusKeys.Trusted] = "1";
            fields[EngineServiceStatusKeys.CheckedAt] =
                observedAt.AddSeconds(-1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            fields[EngineServiceStatusKeys.Ping] = "1";
            fields[EngineServiceStatusKeys.IcmpEnabled] = "0";
            fields[EngineServiceStatusKeys.PhoneConnections] = "";
            fields[EngineServiceStatusKeys.PhoneConnectionsKnown] = "0";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActive] = "";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActiveKnown] = "0";
            fields[EngineServiceStatusKeys.TtlBad] = "0";
            fields[EngineServiceStatusKeys.Ipv6Dropped] = "0";
            fields[EngineServiceStatusKeys.FragmentsDropped] = "0";
            fields[EngineServiceStatusKeys.Stop] = "none";
            fields[EngineServiceStatusKeys.StopAt] = "";
            fields[EngineServiceStatusKeys.Cleanup] = "ok";
            fields[EngineServiceStatusKeys.Admin] = "1";
            return ParseStatus(fields, observedAt);
        }

        private static EngineServiceStatus NoSourceStatus(DateTimeOffset now)
        {
            Dictionary<string, string> fields = ReadyStatusFields(now);
            fields[EngineServiceStatusKeys.Source] = "0";
            fields[EngineServiceStatusKeys.Trusted] = "0";
            fields[EngineServiceStatusKeys.CheckedAt] = "";
            return ParseStatus(fields, now);
        }

        private static EngineServiceStatus StaleReadyStatus(DateTimeOffset now)
        {
            return ReadyStatus(now.AddSeconds(-5), now.AddSeconds(-5));
        }

        private static EngineServiceStatus RunningStatus(DateTimeOffset now)
        {
            return ParseStatus(RunningStatusFields(now), now);
        }

        private static EngineServiceStatus CleanupFailedStatus(DateTimeOffset now)
        {
            Dictionary<string, string> fields = ReadyStatusFields(now);
            fields[EngineServiceStatusKeys.Cleanup] = "failed";
            fields[EngineServiceStatusKeys.Stop] = "unknown";
            fields[EngineServiceStatusKeys.StopAt] =
                now.AddSeconds(-1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            fields[EngineServiceStatusKeys.Paired] = "0";
            fields[EngineServiceStatusKeys.PairedScope] = "none";
            fields[EngineServiceStatusKeys.Source] = "0";
            fields[EngineServiceStatusKeys.Trusted] = "0";
            fields[EngineServiceStatusKeys.CheckedAt] = "";
            return ParseStatus(fields, now);
        }

        private static EngineServiceStatus UnavailableStatus(DateTimeOffset now)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineServiceStatusKeys.Version] = "1";
            fields[EngineServiceStatusKeys.Ok] = "1";
            fields[EngineServiceStatusKeys.Instance] = "service-0001";
            fields[EngineServiceStatusKeys.Engine] = "unavailable";
            fields[EngineServiceStatusKeys.Running] = "0";
            fields[EngineServiceStatusKeys.Mode] = "phone";
            fields[EngineServiceStatusKeys.Paired] = "1";
            fields[EngineServiceStatusKeys.PairedScope] = "session";
            fields[EngineServiceStatusKeys.Source] = "0";
            fields[EngineServiceStatusKeys.Trusted] = "0";
            fields[EngineServiceStatusKeys.CheckedAt] = "";
            fields[EngineServiceStatusKeys.Ping] = "0";
            fields[EngineServiceStatusKeys.IcmpEnabled] = "0";
            fields[EngineServiceStatusKeys.PhoneConnections] = "";
            fields[EngineServiceStatusKeys.PhoneConnectionsKnown] = "0";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActive] = "";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActiveKnown] = "0";
            fields[EngineServiceStatusKeys.TtlBad] = "0";
            fields[EngineServiceStatusKeys.Ipv6Dropped] = "0";
            fields[EngineServiceStatusKeys.FragmentsDropped] = "0";
            fields[EngineServiceStatusKeys.Stop] = "none";
            fields[EngineServiceStatusKeys.StopAt] = "";
            fields[EngineServiceStatusKeys.Cleanup] = "ok";
            fields[EngineServiceStatusKeys.Admin] = "0";
            return ParseStatus(fields, now);
        }

        private static Dictionary<string, string> ReadyStatusFields(DateTimeOffset now)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineServiceStatusKeys.Version] = "1";
            fields[EngineServiceStatusKeys.Ok] = "1";
            fields[EngineServiceStatusKeys.Instance] = "service-0001";
            fields[EngineServiceStatusKeys.Engine] = "ready";
            fields[EngineServiceStatusKeys.Running] = "0";
            fields[EngineServiceStatusKeys.Mode] = "phone";
            fields[EngineServiceStatusKeys.Paired] = "1";
            fields[EngineServiceStatusKeys.PairedScope] = "session";
            fields[EngineServiceStatusKeys.Source] = "1";
            fields[EngineServiceStatusKeys.Trusted] = "1";
            fields[EngineServiceStatusKeys.CheckedAt] =
                now.AddSeconds(-1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            fields[EngineServiceStatusKeys.Ping] = "1";
            fields[EngineServiceStatusKeys.IcmpEnabled] = "0";
            fields[EngineServiceStatusKeys.PhoneConnections] = "";
            fields[EngineServiceStatusKeys.PhoneConnectionsKnown] = "0";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActive] = "";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActiveKnown] = "0";
            fields[EngineServiceStatusKeys.TtlBad] = "0";
            fields[EngineServiceStatusKeys.Ipv6Dropped] = "0";
            fields[EngineServiceStatusKeys.FragmentsDropped] = "0";
            fields[EngineServiceStatusKeys.Stop] = "none";
            fields[EngineServiceStatusKeys.StopAt] = "";
            fields[EngineServiceStatusKeys.Cleanup] = "ok";
            fields[EngineServiceStatusKeys.Admin] = "1";
            return fields;
        }

        private static EngineServiceStatus ParseStatus(
            Dictionary<string, string> fields,
            DateTimeOffset observedAt)
        {
            EngineServiceStatus status;
            string code;
            AssertEx.True(
                EngineServiceStatus.TryParse(fields, observedAt, out status, out code),
                "status parse: " + code);
            return status;
        }

        private static Dictionary<string, string> StartFields(bool ping)
        {
            Dictionary<string, string> fields = RequestFields(EngineProtocol.Operations.Start, Session);
            fields[EngineProtocol.Keys.Ping] = ping ? "1" : "0";
            return fields;
        }

        private static EngineServiceStateRecord NewLaunching(DateTimeOffset now)
        {
            return EngineServiceStateRecord.CreateNeverLaunched(
                    now,
                    "C:\\Program Files\\HotspotShade\\hotspotshade.exe")
                .BeginLaunch("intent-0001", Nonce(), "HotspotShade-test-1", GuidText(), 123, now);
        }

        private static EngineServiceStateRecord NewRunning(DateTimeOffset now)
        {
            return NewLaunching(now)
                .MarkLaunched(1234, 5678, now)
                .MarkAdapterReady(42, GuidText(), now)
                .MarkRunning(now);
        }

        private static string Nonce()
        {
            return new string('a', 64);
        }

        private static string GuidText()
        {
            return "00112233-4455-6677-8899-aabbccddeeff";
        }

        private static DateTimeOffset Now()
        {
            return DateTimeOffset.FromUnixTimeSeconds(1762344000);
        }

        private static int Count(string value)
        {
            int parsed;
            AssertEx.True(EngineWire.TryParseCount(value, out parsed), "count");
            return parsed;
        }

        private static byte[] RawFrame(string json)
        {
            byte[] payload = Encoding.UTF8.GetBytes(json);
            byte[] frame = new byte[payload.Length + 4];
            frame[0] = (byte)(payload.Length >> 24);
            frame[1] = (byte)(payload.Length >> 16);
            frame[2] = (byte)(payload.Length >> 8);
            frame[3] = (byte)payload.Length;
            Buffer.BlockCopy(payload, 0, frame, 4, payload.Length);
            return frame;
        }

        private static T Wait<T>(Task<T> task)
        {
            return task.GetAwaiter().GetResult();
        }

        private static void Wait(Task task)
        {
            task.GetAwaiter().GetResult();
        }

        private static EngineServiceStateGate ReadyGate(DateTimeOffset now)
        {
            return EngineServiceStateGate.FromRecord(
                EngineServiceStateRecord.CreateNeverLaunched(now));
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

        private static string FindRepoRoot()
        {
            DirectoryInfo directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory != null)
            {
                if (Directory.Exists(Path.Combine(directory.FullName, "rust"))
                    && Directory.Exists(Path.Combine(directory.FullName, "windows")))
                {
                    return directory.FullName;
                }
                directory = directory.Parent;
            }
            return null;
        }

        private static IEnumerable<string> Files(string root, string pattern)
        {
            foreach (string file in Directory.EnumerateFiles(root, pattern, SearchOption.AllDirectories))
            {
                string normalized = file.Replace('\\', '/');
                if (normalized.Contains("/bin/") || normalized.Contains("/obj/") || normalized.Contains("/.vs/")
                    || normalized.Contains("/AppPackages/") || normalized.Contains("/TestResults/"))
                {
                    continue;
                }
                yield return file;
            }
        }

        private sealed class SessionClock : IEngineClock
        {
            public SessionClock(DateTimeOffset now)
            {
                Now = now;
            }

            public DateTimeOffset Now { get; set; }
        }

        private sealed class FakeBackend : IEngineServiceBackend
        {
            private int activeCalls;
            private int maxActiveCalls;

            public FakeBackend(EngineServiceStatus status)
            {
                Status = status;
            }

            public EngineServiceStatus Status;
            public bool StartOk = true;
            public bool StopOk = true;
            public bool LastPing;
            public int Starts;
            public int Stops;
            public EngineServiceStopReason LastStop;
            public bool BlockStart;
            public readonly ManualResetEventSlim StartEntered = new ManualResetEventSlim(false);
            public readonly ManualResetEventSlim ReleaseStart = new ManualResetEventSlim(false);

            public int MaxActiveCalls
            {
                get { return Volatile.Read(ref maxActiveCalls); }
            }

            public EngineServiceStatus ReadStatus()
            {
                EnterCall();
                try
                {
                    return Status;
                }
                finally
                {
                    LeaveCall();
                }
            }

            public EngineServiceResult Start(bool ping)
            {
                EnterCall();
                try
                {
                    if (BlockStart)
                    {
                        StartEntered.Set();
                        ReleaseStart.Wait(TimeSpan.FromSeconds(5));
                    }
                    Starts++;
                    LastPing = ping;
                    return StartOk
                        ? EngineServiceResult.Success()
                        : EngineServiceResult.Failure(EngineProtocol.ErrorCodes.RouteSetup);
                }
                finally
                {
                    LeaveCall();
                }
            }

            public EngineServiceResult Stop(EngineServiceStopReason reason)
            {
                EnterCall();
                try
                {
                    Stops++;
                    LastStop = reason;
                    return StopOk
                        ? EngineServiceResult.Success()
                        : EngineServiceResult.Failure(EngineProtocol.ErrorCodes.EngineStopTimeout);
                }
                finally
                {
                    LeaveCall();
                }
            }

            private void EnterCall()
            {
                int active = Interlocked.Increment(ref activeCalls);
                int observed = Volatile.Read(ref maxActiveCalls);
                while (active > observed)
                {
                    int prior = Interlocked.CompareExchange(ref maxActiveCalls, active, observed);
                    if (prior == observed)
                    {
                        return;
                    }
                    observed = prior;
                }
            }

            private void LeaveCall()
            {
                Interlocked.Decrement(ref activeCalls);
            }
        }

        private sealed class FakeProcessProof : IEngineServiceRecordedProcessProof
        {
            private readonly EngineServiceRecordedProcessState state;

            public FakeProcessProof(EngineServiceRecordedProcessState state)
            {
                this.state = state;
            }

            public EngineServiceRecordedProcessState Check(
                int processId,
                long created100ns,
                out string code)
            {
                code = "";
                return state;
            }
        }

        private sealed class ThrowingProcessProof : IEngineServiceRecordedProcessProof
        {
            public EngineServiceRecordedProcessState Check(
                int processId,
                long created100ns,
                out string code)
            {
                code = "";
                throw new InvalidOperationException("proof unavailable");
            }
        }

        private sealed class CancellableFakeBackend :
            IEngineServiceBackend,
            IEngineServiceCancellableBackend
        {
            public CancellableFakeBackend(EngineServiceStatus status)
            {
                Status = status;
            }

            public EngineServiceStatus Status;
            public string StartCode;
            public string StopCode;
            public bool BlockStart;
            public bool BlockStop;
            public int Starts;
            public int Stops;
            public readonly ManualResetEventSlim StartEntered = new ManualResetEventSlim(false);
            public readonly ManualResetEventSlim StopEntered = new ManualResetEventSlim(false);

            public EngineServiceStatus ReadStatus()
            {
                return Status;
            }

            public EngineServiceResult Start(bool ping)
            {
                return Start(ping, CancellationToken.None);
            }

            public EngineServiceResult Stop(EngineServiceStopReason reason)
            {
                return Stop(reason, CancellationToken.None);
            }

            public EngineServiceResult Start(bool ping, CancellationToken cancellationToken)
            {
                Starts++;
                if (BlockStart)
                {
                    StartEntered.Set();
                    cancellationToken.WaitHandle.WaitOne();
                    cancellationToken.ThrowIfCancellationRequested();
                }
                return StartCode == null
                    ? EngineServiceResult.Success()
                    : EngineServiceResult.Failure(StartCode);
            }

            public EngineServiceResult Stop(
                EngineServiceStopReason reason,
                CancellationToken cancellationToken)
            {
                Stops++;
                if (BlockStop)
                {
                    StopEntered.Set();
                    cancellationToken.WaitHandle.WaitOne();
                    cancellationToken.ThrowIfCancellationRequested();
                }
                return StopCode == null
                    ? EngineServiceResult.Success()
                    : EngineServiceResult.Failure(StopCode);
            }
        }

        private sealed class LoopbackChannel : IEngineServiceChannel
        {
            private readonly EngineServiceSession session;

            public LoopbackChannel(EngineServiceSession session)
            {
                this.session = session;
            }

            public async Task<byte[]> ExchangeAsync(
                byte[] requestFrame,
                CancellationToken cancellationToken)
            {
                Dictionary<string, string> fields;
                string code;
                if (!EngineServiceFrame.TryDecode(
                    requestFrame,
                    requestFrame.Length,
                    out fields,
                    out code))
                {
                    return null;
                }
                EngineReply reply = await session.HandleAsync(fields, cancellationToken)
                    .ConfigureAwait(false);
                byte[] frame;
                if (!EngineServiceFrame.TryEncode(reply.Fields, out frame, out code))
                {
                    return null;
                }
                return frame;
            }

            public Task CloseAsync()
            {
                return Task.CompletedTask;
            }
        }

        private sealed class FakeChannel : IEngineServiceChannel
        {
            public readonly List<byte[]> Requests = new List<byte[]>();
            public byte[] Response;
            public bool Throw;
            public bool Hang;
            public bool Closed;

            public async Task<byte[]> ExchangeAsync(byte[] requestFrame, CancellationToken cancellationToken)
            {
                Requests.Add(requestFrame);
                if (Throw)
                {
                    throw new IOException("fake failure");
                }
                if (Hang)
                {
                    await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
                }
                return Response;
            }

            public Task CloseAsync()
            {
                Closed = true;
                return Task.CompletedTask;
            }
        }

        // A channel that reports the caller's per-call budget and an outcome
        // answer. It opens no pipe and runs no exchange.
        private sealed class BudgetChannel : IEngineServiceChannel, IEngineServiceChannelExchange
        {
            public readonly List<byte[]> Requests = new List<byte[]>();
            public readonly List<TimeSpan> Budgets = new List<TimeSpan>();
            public readonly Queue<EngineServiceChannelAnswer> Answers =
                new Queue<EngineServiceChannelAnswer>();
            public bool ThrowCanceled;
            public bool ReturnNull;

            public Task<byte[]> ExchangeAsync(byte[] requestFrame, CancellationToken cancellationToken)
            {
                Requests.Add(requestFrame);
                return Task.FromResult<byte[]>(null);
            }

            public Task<EngineServiceChannelAnswer> ExchangeAsync(
                byte[] requestFrame,
                TimeSpan budget,
                CancellationToken cancellationToken)
            {
                Requests.Add(requestFrame);
                Budgets.Add(budget);
                if (ThrowCanceled)
                {
                    throw new OperationCanceledException();
                }
                if (ReturnNull)
                {
                    return Task.FromResult<EngineServiceChannelAnswer>(null);
                }
                EngineServiceChannelAnswer answer = Answers.Count > 0
                    ? Answers.Dequeue()
                    : EngineServiceChannelAnswer.Failure(EngineProtocol.ErrorCodes.Internal, false);
                return Task.FromResult(answer);
            }

            public Task CloseAsync()
            {
                return Task.CompletedTask;
            }
        }

        private static EngineServiceChannelAnswer SuccessAnswer(
            Dictionary<string, string> fields)
        {
            byte[] frame;
            string code;
            if (!EngineServiceFrame.TryEncode(fields, out frame, out code))
            {
                throw new InvalidOperationException("test reply frame: " + code);
            }
            return EngineServiceChannelAnswer.Success(frame);
        }
    }
}
