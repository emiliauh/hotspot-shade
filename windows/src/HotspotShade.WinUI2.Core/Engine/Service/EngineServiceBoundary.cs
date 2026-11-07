using System;
using System.Collections.Generic;

namespace HotspotShade.WinUI2.Core.Engine.Service
{
    // Fixed names and access rights for the Windows engine service boundary.
    //
    // This class is a reviewable policy table. It opens no service, creates no
    // pipe, and changes no access control entry. The future installer and the
    // future transports must use these constants instead of a local literal.
    //
    // The user access mask omits 0x00000004. On a pipe that bit is
    // FILE_CREATE_PIPE_INSTANCE, and GENERIC_WRITE maps to it. A client that
    // asks for GENERIC_WRITE therefore asks for a right the user ACE does not
    // grant. The denial is intentional. Do not widen the ACE to make a default
    // framework constructor work.
    public static class EngineServiceBoundary
    {
        public const string ServiceName = "HotspotShadeEngineSvc";
        public const string PipeName = @"\\.\pipe\HotspotShade.Engine.v1";

        public const string SystemSid = "S-1-5-18";
        public const string AdministratorsSid = "S-1-5-32-544";

        public const uint FileReadData = 0x00000001;
        public const uint FileWriteData = 0x00000002;
        public const uint FileCreatePipeInstance = 0x00000004;
        public const uint FileReadExtendedAttributes = 0x00000008;
        public const uint FileWriteExtendedAttributes = 0x00000010;
        public const uint FileReadAttributes = 0x00000080;
        public const uint FileWriteAttributes = 0x00000100;
        public const uint Delete = 0x00010000;
        public const uint ReadControl = 0x00020000;
        public const uint WriteDac = 0x00040000;
        public const uint WriteOwner = 0x00080000;
        public const uint Synchronize = 0x00100000;
        public const uint GenericAll = 0x10000000;
        public const uint GenericWrite = 0x40000000;
        public const uint GenericRead = 0x80000000;

        // Pipe creation policy. The service creates one byte-mode, wait-mode,
        // duplex instance with FILE_FLAG_FIRST_PIPE_INSTANCE and
        // PIPE_REJECT_REMOTE_CLIENTS. A second instance is refused. The
        // overlapped flag lets the future host put one absolute deadline on a
        // read with CancelIoEx. These are dwOpenMode and dwPipeMode values,
        // not client access rights.
        //
        // Windows defines byte mode, read mode byte, and wait mode as zero
        // valued constants. A validator cannot test for a zero bit. It must
        // instead refuse every message or nowait bit, and it must compare the
        // complete pipe mode so an unknown bit cannot arrive later.
        public const uint PipeAccessDuplex = 0x00000003;
        public const uint PipeRejectRemoteClients = 0x00000008;
        public const uint PipeTypeByte = 0x00000000;
        public const uint PipeReadmodeByte = 0x00000000;
        public const uint PipeWait = 0x00000000;
        public const uint PipeNowait = 0x00000001;
        public const uint PipeReadmodeMessage = 0x00000002;
        public const uint PipeTypeMessage = 0x00000004;
        public const uint PipeMessageOrNowaitMask =
            PipeNowait | PipeReadmodeMessage | PipeTypeMessage;
        public const uint FileFlagFirstPipeInstance = 0x00080000;
        public const uint FileFlagOverlapped = 0x40000000;
        public const int PipeServerMaxInstances = 1;
        public const int PipeUnlimitedInstances = 255;
        public const uint PipeServerOpenMode =
            PipeAccessDuplex | FileFlagFirstPipeInstance | FileFlagOverlapped;
        public const uint PipeServerMode =
            PipeTypeByte | PipeReadmodeByte | PipeWait | PipeRejectRemoteClients;

        // Read, write, read attributes, write attributes, read the owner, and
        // wait. No create-instance, no delete, no change of the DACL or owner.
        public const uint PipeClientAccess = 0x00120183;

        // GENERIC_READ and GENERIC_WRITE as Windows maps them onto a pipe.
        public const uint GenericReadOnPipe = 0x00120089;
        public const uint GenericWriteOnPipe = 0x00120116;

        public const uint ServiceQueryConfig = 0x0001;
        public const uint ServiceChangeConfig = 0x0002;
        public const uint ServiceQueryStatus = 0x0004;
        public const uint ServiceEnumerateDependents = 0x0008;
        public const uint ServiceStart = 0x0010;
        public const uint ServiceStop = 0x0020;
        public const uint ServicePauseContinue = 0x0040;
        public const uint ServiceInterrogate = 0x0080;
        public const uint ServiceUserDefinedControl = 0x0100;

        // Query status and configuration, start, stop, and interrogate. The
        // configuration right is required by the app server proof. Change
        // configuration is not granted.
        public const uint ServiceClientAccess =
            ServiceQueryConfig
            | ServiceQueryStatus
            | ServiceStart
            | ServiceStop
            | ServiceInterrogate;

        public const uint ScManagerConnect = 0x0001;

        // A protected DACL with exactly SYSTEM, Administrators, and the
        // installing person. GA for SYSTEM and Administrators includes the
        // create-instance right; both can already replace the service. This
        // validates the SID form only. The caller must also resolve the
        // installing account and require SidTypeUser.
        public static bool TryBuildPipeSddl(string userSid, out string sddl)
        {
            sddl = null;
            if (!IsAllowedPipeUserSid(userSid))
            {
                return false;
            }
            sddl = "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120183;;;" + userSid + ")";
            return true;
        }

        public static bool TryBuildServiceSddl(string userSid, out string sddl)
        {
            sddl = null;
            if (!IsAllowedPipeUserSid(userSid))
            {
                return false;
            }
            sddl = "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0xB5;;;" + userSid + ")";
            return true;
        }

        // The future server must call this before CreateNamedPipeW. A missing
        // first-instance flag, a missing overlapped flag, a missing
        // remote-client rejection, a non-byte mode, a nowait mode, or a second
        // instance is refused. The policy allows extra open-mode flags so a
        // host can add SECURITY_SQOS_PRESENT or a write-through flag without
        // changing the required safety set. The pipe mode is exact because
        // every other dwPipeMode bit is either unsafe or already zero.
        public static bool TryValidatePipeServerCreate(
            uint openMode,
            uint pipeMode,
            int maxInstances,
            out string code)
        {
            if ((openMode & PipeAccessDuplex) != PipeAccessDuplex
                || (openMode & FileFlagFirstPipeInstance) == 0
                || (openMode & FileFlagOverlapped) == 0
                || (pipeMode & PipeRejectRemoteClients) == 0
                || (pipeMode & PipeMessageOrNowaitMask) != 0
                || pipeMode != PipeServerMode
                || maxInstances != PipeServerMaxInstances)
            {
                code = EngineProtocol.ErrorCodes.Forbidden;
                return false;
            }
            code = "";
            return true;
        }

        // The exact app request. A subset other than this value is refused so
        // a later edit cannot quietly add a right. This is the value passed to
        // CreateFileW, not GENERIC_READ or GENERIC_WRITE.
        public static bool TryValidatePipeClientAccess(uint access, out string code)
        {
            if (access != PipeClientAccess || HasForbiddenPipeRight(access))
            {
                code = EngineProtocol.ErrorCodes.Forbidden;
                return false;
            }
            code = "";
            return true;
        }

        public static bool TryValidateServiceClientAccess(uint access, out string code)
        {
            if (access != ServiceClientAccess)
            {
                code = EngineProtocol.ErrorCodes.Forbidden;
                return false;
            }
            code = "";
            return true;
        }

        public static bool HasForbiddenPipeRight(uint access)
        {
            return (access & FileCreatePipeInstance) != 0
                || (access & Delete) != 0
                || (access & WriteDac) != 0
                || (access & WriteOwner) != 0;
        }

        // Standard Windows mapping. It exists here so a test can prove that
        // GENERIC_WRITE asks for the create-instance bit on a pipe.
        public static uint MapGenericToPipeAccess(uint genericAccess)
        {
            uint access = 0;
            if ((genericAccess & GenericRead) != 0)
            {
                access |= GenericReadOnPipe;
            }
            if ((genericAccess & GenericWrite) != 0)
            {
                access |= GenericWriteOnPipe;
            }
            if ((genericAccess & GenericAll) != 0)
            {
                access |= 0x001F01FF;
            }
            return access;
        }

        public static IReadOnlyList<KeyValuePair<uint, string>> DescribePipeClientAccess()
        {
            List<KeyValuePair<uint, string>> values = new List<KeyValuePair<uint, string>>();
            values.Add(new KeyValuePair<uint, string>(FileReadData, "read data"));
            values.Add(new KeyValuePair<uint, string>(FileWriteData, "write data"));
            values.Add(new KeyValuePair<uint, string>(FileReadAttributes, "read attributes"));
            values.Add(new KeyValuePair<uint, string>(FileWriteAttributes, "write attributes"));
            values.Add(new KeyValuePair<uint, string>(ReadControl, "read owner"));
            values.Add(new KeyValuePair<uint, string>(Synchronize, "wait"));
            return values.AsReadOnly();
        }

        // A numeric SID only. The value is concatenated into an SDDL string,
        // so a separator, parenthesis, space, or non-ASCII character is
        // refused before it can change the descriptor. At least one
        // sub-authority is required, so an authority-only value such as
        // S-1-5 is not a usable principal. Syntax alone is not enough for an
        // ACE: use IsAllowedPipeUserSid before you build one.
        public static bool IsValidUserSid(string sid)
        {
            if (string.IsNullOrEmpty(sid) || sid.Length > 184)
            {
                return false;
            }
            string[] parts = sid.Split('-');
            if (parts.Length < 4 || parts.Length > 18)
            {
                return false;
            }
            if (parts[0] != "S" || parts[1] != "1")
            {
                return false;
            }
            ulong authority;
            if (!TryParseNumeric(parts[2], 15, out authority) || authority > 0xFFFFFFFFFFFFUL)
            {
                return false;
            }
            for (int index = 3; index < parts.Length; index++)
            {
                ulong value;
                if (!TryParseNumeric(parts[index], 10, out value) || value > 0xFFFFFFFFUL)
                {
                    return false;
                }
            }
            return true;
        }

        // The installing SID must have a person-account form, not a
        // well-known group, service, or authority form. This is a form check,
        // not an account-type proof: a custom group can share the S-1-5-21
        // form. The future host must resolve the account type with
        // LookupAccountSid and require SidTypeUser. This allowlist keeps
        // Everyone, Authenticated Users, Users, Administrators, SYSTEM, and
        // the other well-known principals out of the user ACE.
        public static bool IsAllowedPipeUserSid(string sid)
        {
            if (!IsValidUserSid(sid))
            {
                return false;
            }
            string[] parts = sid.Split('-');
            ulong authority;
            if (!TryParseNumeric(parts[2], 15, out authority))
            {
                return false;
            }
            if (authority == 5)
            {
                ulong first;
                if (!TryParseNumeric(parts[3], 10, out first))
                {
                    return false;
                }
                if (first == 21)
                {
                    // Domain or local account: three domain sub-authorities
                    // and one relative id.
                    return parts.Length >= 8;
                }
                return false;
            }
            if (authority == 11 || authority == 12)
            {
                return parts.Length >= 5;
            }
            return false;
        }

        private static bool TryParseNumeric(string text, int maxDigits, out ulong value)
        {
            value = 0;
            if (string.IsNullOrEmpty(text) || text.Length > maxDigits)
            {
                return false;
            }
            if (text.Length > 1 && text[0] == '0')
            {
                return false;
            }
            for (int index = 0; index < text.Length; index++)
            {
                char character = text[index];
                if (character < '0' || character > '9')
                {
                    return false;
                }
                value = (value * 10) + (ulong)(character - '0');
            }
            return true;
        }
    }
}
