using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace HotspotShade.WinUI2.Core.App
{
    // The result of one install-location check in the elevated starter.
    public enum InstallCheck
    {
        Trusted = 0,
        // The file or folder does not exist.
        Missing = 1,
        // The final path is not below a WindowsApps package store.
        NotPackageStore = 2,
        // The final path of a file or folder is not where the package puts
        // it (for example, a link that leads out of the package).
        OutsideRoot = 3,
        // The owner is not TrustedInstaller or SYSTEM.
        OwnerUntrusted = 4,
        // The object has no DACL, so everyone has full access.
        NoDacl = 5,
        // An allow entry gives a change right to an account other than
        // TrustedInstaller, SYSTEM, or Administrators.
        WritableByOthers = 6,
        // The DACL holds an entry type that this check does not know.
        UnsupportedEntry = 7,
        // The owner or the DACL could not be read or parsed.
        Malformed = 8
    }

    // One access control entry, as the starter read it from the DACL.
    public sealed class InstallAce
    {
        public InstallAce(byte type, byte flags, uint mask, string sid)
        {
            Type = type;
            Flags = flags;
            Mask = mask;
            Sid = sid;
        }

        public byte Type { get; private set; }

        public byte Flags { get; private set; }

        public uint Mask { get; private set; }

        // The SID in string form (S-1-...), or null for an entry type that
        // carries no SID that this check reads.
        public string Sid { get; private set; }
    }

    // The pure part of the elevated starter's install-location check. The
    // starter opens each folder and file, asks Windows for its final path,
    // owner, and DACL, and passes the raw bytes here. Nothing in this class
    // calls Windows, so the tests can use fake SIDs and ACEs.
    //
    // The rule for every checked object:
    // 1. The owner is TrustedInstaller or SYSTEM. An owner can always change
    //    the DACL, so any other owner could make the folder writable.
    // 2. A DACL is present. A missing (null) DACL grants everyone full access.
    // 3. No allow entry gives a right that changes the object (write data,
    //    add file, add subfolder, delete, delete child, write attributes,
    //    WRITE_DAC, WRITE_OWNER, or a generic write or all) to any account
    //    other than TrustedInstaller, SYSTEM, or Administrators. That
    //    rejects Users, Authenticated Users, Everyone, INTERACTIVE, the
    //    creator SIDs, and any single user account. Inherit-only entries
    //    count too: they decide the rights on new files.
    // 4. Deny entries never grant a right, so they are skipped. An entry
    //    type that this check does not know rejects the object.
    public static class InstallSecurity
    {
        public const string TrustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        public const string SystemSid = "S-1-5-18";
        public const string AdministratorsSid = "S-1-5-32-544";
        public const string UsersSid = "S-1-5-32-545";
        public const string AuthenticatedUsersSid = "S-1-5-11";
        public const string EveryoneSid = "S-1-1-0";
        public const string CreatorOwnerSid = "S-1-3-0";
        public const string OwnerRightsSid = "S-1-3-4";

        // FILE_WRITE_DATA / FILE_ADD_FILE.
        public const uint WriteData = 0x00000002;
        // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY.
        public const uint AppendData = 0x00000004;
        public const uint WriteExtendedAttributes = 0x00000010;
        public const uint DeleteChild = 0x00000040;
        public const uint WriteAttributes = 0x00000100;
        public const uint Delete = 0x00010000;
        public const uint WriteDac = 0x00040000;
        public const uint WriteOwner = 0x00080000;
        public const uint MaximumAllowed = 0x02000000;
        public const uint GenericAll = 0x10000000;
        public const uint GenericWrite = 0x40000000;

        // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE: what Users get on an
        // installed package folder.
        public const uint ReadAndExecute = 0x001200A9;

        public const uint ChangeRights = WriteData | AppendData | WriteExtendedAttributes | DeleteChild
            | WriteAttributes | Delete | WriteDac | WriteOwner | MaximumAllowed | GenericAll | GenericWrite;

        public const byte AccessAllowed = 0x00;
        public const byte AccessDenied = 0x01;
        public const byte AccessAllowedObject = 0x05;
        public const byte AccessDeniedObject = 0x06;
        public const byte AccessAllowedCallback = 0x09;
        public const byte AccessDeniedCallback = 0x0A;
        public const byte AccessAllowedCallbackObject = 0x0B;
        public const byte AccessDeniedCallbackObject = 0x0C;

        public const byte InheritOnly = 0x08;

        private const int MaxSubAuthorities = 15;

        public static bool IsTrustedOwner(string sid)
        {
            return sid == TrustedInstallerSid || sid == SystemSid;
        }

        // The accounts that may hold a change right on the package. An
        // administrator can already change anything on the machine.
        public static bool MayChange(string sid)
        {
            return sid == TrustedInstallerSid || sid == SystemSid || sid == AdministratorsSid;
        }

        // The rule above, on parsed values. hasDacl is false for a null DACL.
        public static InstallCheck Evaluate(string ownerSid, bool hasDacl, IList<InstallAce> aces)
        {
            if (string.IsNullOrEmpty(ownerSid))
            {
                return InstallCheck.Malformed;
            }
            if (!IsTrustedOwner(ownerSid))
            {
                return InstallCheck.OwnerUntrusted;
            }
            if (!hasDacl)
            {
                return InstallCheck.NoDacl;
            }
            if (aces == null)
            {
                return InstallCheck.Malformed;
            }
            for (int index = 0; index < aces.Count; index++)
            {
                InstallAce ace = aces[index];
                if (ace == null)
                {
                    return InstallCheck.Malformed;
                }
                if (IsDeny(ace.Type))
                {
                    continue;
                }
                if (!IsAllow(ace.Type))
                {
                    return InstallCheck.UnsupportedEntry;
                }
                if (string.IsNullOrEmpty(ace.Sid))
                {
                    return InstallCheck.Malformed;
                }
                if ((ace.Mask & ChangeRights) != 0 && !MayChange(ace.Sid))
                {
                    return InstallCheck.WritableByOthers;
                }
            }
            return InstallCheck.Trusted;
        }

        // The rule above, on the raw owner SID and DACL bytes that
        // GetSecurityInfo returned. A null dacl is a missing DACL.
        public static InstallCheck Evaluate(byte[] owner, byte[] dacl)
        {
            string ownerSid;
            int length;
            if (owner == null || !TryParseSid(owner, 0, owner.Length, out ownerSid, out length) || length != owner.Length)
            {
                return InstallCheck.Malformed;
            }
            if (dacl == null)
            {
                return Evaluate(ownerSid, false, null);
            }
            List<InstallAce> aces;
            if (!TryParseAcl(dacl, out aces))
            {
                // Report the owner first, so a user-owned folder reads as
                // such even when its DACL is odd.
                return IsTrustedOwner(ownerSid) ? InstallCheck.Malformed : InstallCheck.OwnerUntrusted;
            }
            return Evaluate(ownerSid, true, aces);
        }

        public static bool IsAllow(byte type)
        {
            return type == AccessAllowed || type == AccessAllowedObject
                || type == AccessAllowedCallback || type == AccessAllowedCallbackObject;
        }

        public static bool IsDeny(byte type)
        {
            return type == AccessDenied || type == AccessDeniedObject
                || type == AccessDeniedCallback || type == AccessDeniedCallbackObject;
        }

        // Reads a binary SID at offset, ending no later than limit. The
        // string form matches ConvertSidToStringSidW.
        public static bool TryParseSid(byte[] data, int offset, int limit, out string sid, out int length)
        {
            sid = null;
            length = 0;
            if (data == null || offset < 0 || limit > data.Length || offset + 8 > limit)
            {
                return false;
            }
            int count = data[offset + 1];
            if (data[offset] != 1 || count > MaxSubAuthorities)
            {
                return false;
            }
            int size = 8 + (4 * count);
            if (offset + size > limit)
            {
                return false;
            }
            ulong authority = 0;
            for (int index = 0; index < 6; index++)
            {
                authority = (authority << 8) | data[offset + 2 + index];
            }
            StringBuilder text = new StringBuilder("S-1-");
            if (authority <= uint.MaxValue)
            {
                text.Append(authority.ToString(CultureInfo.InvariantCulture));
            }
            else
            {
                text.Append("0x");
                text.Append(authority.ToString("X12", CultureInfo.InvariantCulture));
            }
            for (int index = 0; index < count; index++)
            {
                text.Append('-');
                text.Append(ReadUInt32(data, offset + 8 + (4 * index)).ToString(CultureInfo.InvariantCulture));
            }
            sid = text.ToString();
            length = size;
            return true;
        }

        // Reads an ACL (header and entries). Any length or layout that does
        // not add up refuses the whole ACL.
        public static bool TryParseAcl(byte[] acl, out List<InstallAce> aces)
        {
            aces = null;
            if (acl == null || acl.Length < 8)
            {
                return false;
            }
            if (acl[0] != 2 && acl[0] != 4)
            {
                return false;
            }
            int size = acl[2] | (acl[3] << 8);
            int count = acl[4] | (acl[5] << 8);
            if (size < 8 || size > acl.Length)
            {
                return false;
            }
            List<InstallAce> result = new List<InstallAce>(count);
            int offset = 8;
            for (int index = 0; index < count; index++)
            {
                if (offset + 4 > size)
                {
                    return false;
                }
                byte type = acl[offset];
                byte flags = acl[offset + 1];
                int aceSize = acl[offset + 2] | (acl[offset + 3] << 8);
                if (aceSize < 4 || (aceSize & 3) != 0 || offset + aceSize > size)
                {
                    return false;
                }
                int end = offset + aceSize;
                uint mask = 0;
                string sid = null;
                int sidAt = -1;
                switch (type)
                {
                    case AccessAllowed:
                    case AccessDenied:
                    case AccessAllowedCallback:
                    case AccessDeniedCallback:
                        if (offset + 8 > end)
                        {
                            return false;
                        }
                        mask = ReadUInt32(acl, offset + 4);
                        sidAt = offset + 8;
                        break;
                    case AccessAllowedObject:
                    case AccessDeniedObject:
                    case AccessAllowedCallbackObject:
                    case AccessDeniedCallbackObject:
                        if (offset + 12 > end)
                        {
                            return false;
                        }
                        mask = ReadUInt32(acl, offset + 4);
                        uint objectFlags = ReadUInt32(acl, offset + 8);
                        sidAt = offset + 12 + ((objectFlags & 1) != 0 ? 16 : 0) + ((objectFlags & 2) != 0 ? 16 : 0);
                        break;
                }
                if (sidAt >= 0)
                {
                    int sidLength;
                    if (!TryParseSid(acl, sidAt, end, out sid, out sidLength))
                    {
                        return false;
                    }
                }
                result.Add(new InstallAce(type, flags, mask, sid));
                offset = end;
            }
            aces = result;
            return true;
        }

        // The path form of a GetFinalPathNameByHandleW(VOLUME_NAME_DOS)
        // answer: \\?\C:\x becomes C:\x. A network path, a device path, or
        // any odd segment gives null.
        public static string NormalizeFinalPath(string finalPath)
        {
            if (string.IsNullOrEmpty(finalPath))
            {
                return null;
            }
            string path = finalPath;
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
            {
                path = path.Substring(4);
            }
            if (path.Length < 3 || !IsDriveLetter(path[0]) || path[1] != ':' || path[2] != '\\')
            {
                return null;
            }
            // A final path holds long names only, so a short-name `~` is not
            // refused here (package folder names may hold `~`). A `:` after
            // the drive names an alternate data stream.
            if (path.IndexOf('/') >= 0 || path.IndexOf('\0') >= 0 || path.IndexOf(':', 2) >= 0
                || path.IndexOf("\\\\", StringComparison.Ordinal) >= 0)
            {
                return null;
            }
            string trimmed = path.Length > 3 ? path.TrimEnd('\\') : path;
            string[] parts = trimmed.Split('\\');
            for (int index = 1; index < parts.Length; index++)
            {
                string part = parts[index];
                if (part.Length == 0 && trimmed.Length == 3)
                {
                    continue;
                }
                // Win32 path parsing drops a trailing dot or space, so a
                // folder verified as "Engine." through \\?\ would start as
                // "Engine". Such names never appear in a package.
                if (part.Length == 0 || part == "." || part == ".."
                    || part[part.Length - 1] == '.' || part[part.Length - 1] == ' ')
                {
                    return null;
                }
            }
            return trimmed;
        }

        // GetDriveTypeW: only a fixed local disk can hold a trusted install.
        // Removable media can be changed on another computer, and a network
        // drive is controlled by its server.
        public const uint DriveFixed = 3;

        public static bool IsTrustedDriveType(uint driveType)
        {
            return driveType == DriveFixed;
        }

        // A package full name as Windows reports it (GetPackageFullName):
        // letters, digits, and . _ - ~, at most 127 characters.
        public static bool IsPackageFullName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length > 127 || name == "." || name == "..")
            {
                return false;
            }
            for (int index = 0; index < name.Length; index++)
            {
                char value = name[index];
                bool ok = (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9')
                    || value == '.' || value == '_' || value == '-' || value == '~';
                if (!ok)
                {
                    return false;
                }
            }
            return true;
        }

        // True when the package root is the install folder of the broker's
        // own package: its folder name is the package full name, and it is
        // the path that Windows reports for that package
        // (GetPackagePathByFullName, resolved to its final path). This ties
        // the root to a package that Windows installed, not to any folder
        // that only looks like a package store.
        public static bool MatchesPackage(string rootFinal, string packageFullName, string packagePathFinal)
        {
            return RootNamesPackage(rootFinal, packageFullName) && SameFinalPath(packagePathFinal, rootFinal);
        }

        // The first half of MatchesPackage: the root folder's name is the
        // package full name. The starter checks it against the pipe server's
        // package before it reads the request.
        public static bool RootNamesPackage(string rootFinal, string packageFullName)
        {
            string root = NormalizeFinalPath(rootFinal);
            if (root == null || !IsPackageFullName(packageFullName))
            {
                return false;
            }
            int slash = root.LastIndexOf('\\');
            return slash >= 2 && string.Equals(root.Substring(slash + 1), packageFullName, StringComparison.OrdinalIgnoreCase);
        }

        // The package root of a starter whose final image path is
        // <root>\Elevate\<StarterFileName>, or null.
        public static string RootFromStarter(string starterFinalPath)
        {
            string path = NormalizeFinalPath(starterFinalPath);
            if (path == null)
            {
                return null;
            }
            string suffix = "\\Elevate\\" + ElevationProtocol.StarterFileName;
            if (path.Length <= suffix.Length + 3 || !path.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
            return path.Substring(0, path.Length - suffix.Length);
        }

        // True when the final path of the package root is in a package store.
        // programFilesFinal is the resolved Program Files folder, or null.
        public static bool IsPackageStoreLocation(string rootFinal, string programFilesFinal)
        {
            string root = NormalizeFinalPath(rootFinal);
            if (root == null)
            {
                return false;
            }
            return InstallRules.IsPackageStorePath(root, NormalizeFinalPath(programFilesFinal));
        }

        // True when the two final paths name the same object.
        public static bool SameFinalPath(string left, string right)
        {
            string a = NormalizeFinalPath(left);
            string b = NormalizeFinalPath(right);
            return a != null && b != null && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        }

        // True when child is strictly below parent.
        public static bool IsInsideFinalPath(string child, string parent)
        {
            string inside = NormalizeFinalPath(child);
            string root = NormalizeFinalPath(parent);
            if (inside == null || root == null || root.Length <= 3)
            {
                return false;
            }
            return inside.Length > root.Length + 1
                && inside.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase);
        }

        // The starter's reply for a failed check. A missing file has its own
        // code; every other failure is an untrusted install.
        public static ElevationReplyCode ReplyFor(InstallCheck check, ElevationReplyCode missing)
        {
            switch (check)
            {
                case InstallCheck.Trusted:
                    return ElevationReplyCode.Started;
                case InstallCheck.Missing:
                    return missing;
                default:
                    return ElevationReplyCode.InstallUntrusted;
            }
        }

        private static bool IsDriveLetter(char value)
        {
            return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
        }

        private static uint ReadUInt32(byte[] data, int offset)
        {
            return (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
        }
    }
}
