using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using HotspotShade.WinUI2.Core.App;

namespace HotspotShade.WinUI2.Core.Tests
{
    // Checks for the elevated starter's install-location rule with fake SIDs
    // and ACEs in the binary layout that GetSecurityInfo returns. Nothing
    // here calls Windows.
    internal static class InstallSecurityTests
    {
        private const string UserSid = "S-1-5-21-1004336348-1177238915-682003330-1001";
        private const string AllPackagesSid = "S-1-15-2-1";
        private const string PackageSid = "S-1-15-2-2434737943-167758768-3180539153-984336765-1107280622-3591121930-2677285773";
        private const string InteractiveSid = "S-1-5-4";
        private const uint FullControl = 0x001F01FF;
        private const byte ObjectInherit = 0x01;
        private const byte ContainerInherit = 0x02;

        public static void Run(TestRunner runner)
        {
            runner.Check("install security: SIDs read like ConvertSidToStringSid", delegate
            {
                foreach (string sid in new[]
                {
                    InstallSecurity.TrustedInstallerSid, InstallSecurity.SystemSid, InstallSecurity.UsersSid,
                    InstallSecurity.EveryoneSid, InstallSecurity.CreatorOwnerSid, UserSid, PackageSid
                })
                {
                    byte[] bytes = SidBytes(sid);
                    string parsed;
                    int length;
                    AssertEx.True(InstallSecurity.TryParseSid(bytes, 0, bytes.Length, out parsed, out length), "parse " + sid);
                    AssertEx.Equal(sid, parsed, "round trip");
                    AssertEx.Equal(bytes.Length, length, "length");
                }
                byte[] wide = { 1, 1, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 7, 0, 0, 0 };
                string hex;
                int wideLength;
                AssertEx.True(InstallSecurity.TryParseSid(wide, 0, wide.Length, out hex, out wideLength), "large authority");
                AssertEx.Equal("S-1-0x123456789ABC-7", hex, "hex authority");
                byte[] tooMany = new byte[8 + (16 * 4)];
                tooMany[0] = 1;
                tooMany[1] = 16;
                AssertEx.False(InstallSecurity.TryParseSid(tooMany, 0, tooMany.Length, out hex, out wideLength), "16 sub-authorities");
                byte[] system = SidBytes(InstallSecurity.SystemSid);
                AssertEx.False(InstallSecurity.TryParseSid(system, 0, system.Length - 1, out hex, out wideLength), "truncated");
                system[0] = 2;
                AssertEx.False(InstallSecurity.TryParseSid(system, 0, system.Length, out hex, out wideLength), "revision");
            });

            runner.Check("install security: an installed package folder is trusted", delegate
            {
                byte[] acl = PackageAcl();
                AssertEx.Equal(InstallCheck.Trusted, InstallSecurity.Evaluate(SidBytes(InstallSecurity.TrustedInstallerSid), acl), "TrustedInstaller owner");
                AssertEx.Equal(InstallCheck.Trusted, InstallSecurity.Evaluate(SidBytes(InstallSecurity.SystemSid), acl), "SYSTEM owner");
                AssertEx.Equal(InstallCheck.Trusted, InstallSecurity.Evaluate(SidBytes(InstallSecurity.TrustedInstallerSid), Acl()), "empty DACL grants nothing");
                byte[] adminFull = Acl(Ace(InstallSecurity.AccessAllowed, 0, FullControl, InstallSecurity.AdministratorsSid),
                    Ace(InstallSecurity.AccessAllowed, 0, InstallSecurity.GenericAll, InstallSecurity.SystemSid));
                AssertEx.Equal(InstallCheck.Trusted, InstallSecurity.Evaluate(SidBytes(InstallSecurity.TrustedInstallerSid), adminFull), "administrators and SYSTEM may change it");
            });

            runner.Check("install security: only TrustedInstaller or SYSTEM may own it", delegate
            {
                byte[] acl = PackageAcl();
                AssertEx.Equal(InstallCheck.OwnerUntrusted, InstallSecurity.Evaluate(SidBytes(UserSid), acl), "user owner");
                AssertEx.Equal(InstallCheck.OwnerUntrusted, InstallSecurity.Evaluate(SidBytes(InstallSecurity.AdministratorsSid), acl), "administrators owner");
                AssertEx.Equal(InstallCheck.OwnerUntrusted, InstallSecurity.Evaluate(SidBytes(InstallSecurity.UsersSid), acl), "users owner");
                AssertEx.Equal(InstallCheck.OwnerUntrusted, InstallSecurity.Evaluate(UserSid, true, new List<InstallAce>()), "parsed user owner");
                AssertEx.Equal(InstallCheck.Malformed, InstallSecurity.Evaluate(null, true, new List<InstallAce>()), "no owner");
            });

            runner.Check("install security: a missing DACL is refused", delegate
            {
                AssertEx.Equal(InstallCheck.NoDacl, InstallSecurity.Evaluate(SidBytes(InstallSecurity.TrustedInstallerSid), null), "null DACL");
                AssertEx.Equal(InstallCheck.NoDacl, InstallSecurity.Evaluate(InstallSecurity.SystemSid, false, null), "parsed null DACL");
            });

            runner.Check("install security: no change right for users, everyone, or creator SIDs", delegate
            {
                byte[] owner = SidBytes(InstallSecurity.TrustedInstallerSid);
                var cases = new[]
                {
                    Tuple.Create(InstallSecurity.UsersSid, InstallSecurity.WriteData, (byte)0, "Users write data / add file"),
                    Tuple.Create(InstallSecurity.AuthenticatedUsersSid, InstallSecurity.AppendData, (byte)0, "Authenticated Users add subfolder"),
                    Tuple.Create(InstallSecurity.EveryoneSid, InstallSecurity.GenericWrite, (byte)0, "Everyone generic write"),
                    Tuple.Create(InstallSecurity.UsersSid, InstallSecurity.Delete, (byte)0, "Users delete"),
                    Tuple.Create(InstallSecurity.UsersSid, InstallSecurity.DeleteChild, (byte)0, "Users delete child"),
                    Tuple.Create(InstallSecurity.UsersSid, InstallSecurity.WriteDac, (byte)0, "Users WRITE_DAC"),
                    Tuple.Create(InstallSecurity.EveryoneSid, InstallSecurity.WriteOwner, (byte)0, "Everyone WRITE_OWNER"),
                    Tuple.Create(InstallSecurity.CreatorOwnerSid, InstallSecurity.GenericAll, (byte)(ObjectInherit | ContainerInherit | InstallSecurity.InheritOnly), "CREATOR OWNER inherit-only full"),
                    Tuple.Create(InstallSecurity.OwnerRightsSid, InstallSecurity.WriteDac, (byte)0, "OWNER RIGHTS WRITE_DAC"),
                    Tuple.Create(InteractiveSid, InstallSecurity.WriteAttributes, (byte)0, "INTERACTIVE write attributes"),
                    Tuple.Create(UserSid, FullControl, (byte)0, "one user account"),
                    Tuple.Create(PackageSid, InstallSecurity.WriteData, (byte)0, "a package SID")
                };
                foreach (var item in cases)
                {
                    byte[] acl = PackageAcl(Ace(InstallSecurity.AccessAllowed, item.Item3, item.Item2, item.Item1));
                    AssertEx.Equal(InstallCheck.WritableByOthers, InstallSecurity.Evaluate(owner, acl), item.Item4);
                }
            });

            runner.Check("install security: deny entries are skipped and other entry types are judged", delegate
            {
                byte[] owner = SidBytes(InstallSecurity.TrustedInstallerSid);
                byte[] deny = PackageAcl(Ace(InstallSecurity.AccessDenied, 0, FullControl, InstallSecurity.UsersSid));
                AssertEx.Equal(InstallCheck.Trusted, InstallSecurity.Evaluate(owner, deny), "a deny entry grants nothing");
                byte[] objectAce = PackageAcl(ObjectAce(InstallSecurity.AccessAllowedObject, InstallSecurity.WriteData, 3, InstallSecurity.UsersSid));
                AssertEx.Equal(InstallCheck.WritableByOthers, InstallSecurity.Evaluate(owner, objectAce), "object entry with both GUIDs");
                byte[] objectRead = PackageAcl(ObjectAce(InstallSecurity.AccessAllowedObject, InstallSecurity.ReadAndExecute, 1, InstallSecurity.UsersSid));
                AssertEx.Equal(InstallCheck.Trusted, InstallSecurity.Evaluate(owner, objectRead), "object entry with read only");
                byte[] callback = PackageAcl(Ace(InstallSecurity.AccessAllowedCallback, 0, InstallSecurity.WriteData, InstallSecurity.UsersSid));
                AssertEx.Equal(InstallCheck.WritableByOthers, InstallSecurity.Evaluate(owner, callback), "a conditional entry counts as a grant");
                byte[] withData = Ace(InstallSecurity.AccessAllowedCallback, 0, InstallSecurity.ReadAndExecute, InstallSecurity.UsersSid);
                byte[] padded = new byte[withData.Length + 8];
                Array.Copy(withData, padded, withData.Length);
                padded[withData.Length] = 0x61;
                padded[2] = (byte)padded.Length;
                AssertEx.Equal(InstallCheck.Trusted, InstallSecurity.Evaluate(owner, PackageAcl(padded)), "a conditional read entry with data after the SID");
                byte[] shortObject = ObjectAce(InstallSecurity.AccessAllowedObject, InstallSecurity.ReadAndExecute, 0, InstallSecurity.UsersSid);
                WriteUInt32(shortObject, 8, 3);
                AssertEx.Equal(InstallCheck.Malformed, InstallSecurity.Evaluate(owner, PackageAcl(shortObject)), "GUID flags push the SID past the entry");
                byte[] revision4 = PackageAcl(ObjectAce(InstallSecurity.AccessAllowedObject, InstallSecurity.ReadAndExecute, 2, InstallSecurity.UsersSid));
                revision4[0] = 4;
                AssertEx.Equal(InstallCheck.Trusted, InstallSecurity.Evaluate(owner, revision4), "a revision 4 ACL");
                byte[] label = PackageAcl(Ace(0x11, 0, 0x1, "S-1-16-12288"));
                AssertEx.Equal(InstallCheck.UnsupportedEntry, InstallSecurity.Evaluate(owner, label), "unknown entry type in a DACL");
            });

            runner.Check("install security: odd ACL bytes are refused", delegate
            {
                byte[] owner = SidBytes(InstallSecurity.TrustedInstallerSid);
                byte[] good = PackageAcl();
                byte[] truncated = new byte[good.Length - 4];
                Array.Copy(good, truncated, truncated.Length);
                AssertEx.Equal(InstallCheck.Malformed, InstallSecurity.Evaluate(owner, truncated), "size beyond the buffer");
                byte[] count = (byte[])good.Clone();
                count[4] = (byte)(count[4] + 1);
                AssertEx.Equal(InstallCheck.Malformed, InstallSecurity.Evaluate(owner, count), "more entries than bytes");
                byte[] revision = (byte[])good.Clone();
                revision[0] = 3;
                AssertEx.Equal(InstallCheck.Malformed, InstallSecurity.Evaluate(owner, revision), "revision");
                byte[] odd = (byte[])good.Clone();
                odd[8 + 2] = (byte)(odd[8 + 2] + 1);
                AssertEx.Equal(InstallCheck.Malformed, InstallSecurity.Evaluate(owner, odd), "entry size not a multiple of four");
                byte[] badSid = (byte[])good.Clone();
                badSid[8 + 8] = 9;
                AssertEx.Equal(InstallCheck.Malformed, InstallSecurity.Evaluate(owner, badSid), "SID revision inside an entry");
                AssertEx.Equal(InstallCheck.OwnerUntrusted, InstallSecurity.Evaluate(SidBytes(UserSid), truncated), "a user owner reads as such");
                byte[] longOwner = new byte[owner.Length + 4];
                Array.Copy(owner, longOwner, owner.Length);
                AssertEx.Equal(InstallCheck.Malformed, InstallSecurity.Evaluate(longOwner, good), "trailing owner bytes");
            });

            runner.Check("install security: final paths, the starter root, and the package store", delegate
            {
                AssertEx.Equal(@"C:\Program Files\WindowsApps\Pkg", InstallSecurity.NormalizeFinalPath(@"\\?\C:\Program Files\WindowsApps\Pkg\"), "final path form");
                AssertEx.True(InstallSecurity.NormalizeFinalPath(@"\\?\UNC\server\share\WindowsApps\Pkg") == null, "network path");
                AssertEx.True(InstallSecurity.NormalizeFinalPath(@"\\.\pipe\x") == null, "device path");
                AssertEx.True(InstallSecurity.NormalizeFinalPath(@"\\?\GLOBALROOT\Device\HarddiskVolume3\x") == null, "volume GUID or device form");
                AssertEx.True(InstallSecurity.NormalizeFinalPath(@"C:\WindowsApps\Pkg\..\Other") == null, "traversal");
                AssertEx.True(InstallSecurity.NormalizeFinalPath(@"\\?\C:\Program Files\WindowsApps\Pkg\Engine.") == null, "trailing dot");
                AssertEx.True(InstallSecurity.NormalizeFinalPath(@"\\?\C:\Program Files\WindowsApps\Pkg\Engine \hotspotshade.exe") == null, "trailing space");
                AssertEx.True(InstallSecurity.NormalizeFinalPath(@"\\?\C:\Program Files\WindowsApps\Pkg\Engine\wintun.dll:evil") == null, "alternate data stream");
                AssertEx.Equal(@"C:\Program Files\WindowsApps\A_1.0.0.0_neutral_~_abc", InstallSecurity.NormalizeFinalPath(@"\\?\C:\Program Files\WindowsApps\A_1.0.0.0_neutral_~_abc"), "a ~ in a long name");

                string starter = @"\\?\C:\Program Files\WindowsApps\HotspotShade.Windows_0.2.0.0_x64__abc\Elevate\HotspotShade.WinUI2.Elevate.exe";
                AssertEx.Equal(@"C:\Program Files\WindowsApps\HotspotShade.Windows_0.2.0.0_x64__abc", InstallSecurity.RootFromStarter(starter), "root from the starter image");
                AssertEx.True(InstallSecurity.RootFromStarter(@"\\?\C:\Program Files\WindowsApps\Pkg\Elevate\other.exe") == null, "other file name");
                AssertEx.True(InstallSecurity.RootFromStarter(@"\\?\C:\Elevate\HotspotShade.WinUI2.Elevate.exe") == null, "drive root");
                AssertEx.True(InstallSecurity.RootFromStarter(@"\\?\C:\Program Files\WindowsApps\Pkg\Broker\HotspotShade.WinUI2.Elevate.exe") == null, "other folder");

                AssertEx.True(InstallSecurity.IsPackageStoreLocation(@"\\?\C:\Program Files\WindowsApps\Pkg", @"\\?\C:\Program Files"), "Program Files store");
                AssertEx.True(InstallSecurity.IsPackageStoreLocation(@"\\?\D:\WindowsApps\Pkg", @"\\?\C:\Program Files"), "another volume is a location only");
                AssertEx.False(InstallSecurity.IsPackageStoreLocation(@"\\?\C:\Users\me\source\AppX", @"\\?\C:\Program Files"), "user folder");
                AssertEx.False(InstallSecurity.IsPackageStoreLocation(@"\\?\UNC\srv\WindowsApps\Pkg", @"\\?\C:\Program Files"), "network store");
                AssertEx.False(InstallSecurity.IsPackageStoreLocation(@"\\?\C:\Program Files\WindowsApps", @"\\?\C:\Program Files"), "the store itself");

                string root = @"C:\Program Files\WindowsApps\Pkg";
                AssertEx.True(InstallSecurity.IsInsideFinalPath(@"\\?\C:\Program Files\WindowsApps\PKG\Engine\hotspotshade.exe", root), "inside, any case");
                AssertEx.False(InstallSecurity.IsInsideFinalPath(@"\\?\C:\Program Files\WindowsApps\Pkg2\Engine\hotspotshade.exe", root), "a sibling with the same prefix");
                AssertEx.False(InstallSecurity.IsInsideFinalPath(@"\\?\C:\Users\me\Engine\hotspotshade.exe", root), "a link out of the package");
                AssertEx.True(InstallSecurity.SameFinalPath(@"\\?\C:\Program Files\WindowsApps\Pkg\Engine", root + @"\engine"), "same object");
                AssertEx.False(InstallSecurity.SameFinalPath(@"\\?\D:\Elsewhere\Engine", root + @"\Engine"), "redirected folder");
            });

            runner.Check("install security: the root is the broker's package folder on a fixed disk", delegate
            {
                string name = "HotspotShade.Windows_0.2.0.0_x64__8wekyb3d8bbwe";
                string root = @"\\?\C:\Program Files\WindowsApps\" + name;
                AssertEx.True(InstallSecurity.IsPackageFullName(name), "package full name");
                AssertEx.True(InstallSecurity.IsPackageFullName("A_1.0.0.0_neutral_~_abc"), "bundle-style name");
                AssertEx.False(InstallSecurity.IsPackageFullName(@"..\x"), "path characters");
                AssertEx.False(InstallSecurity.IsPackageFullName(null), "no package identity");
                AssertEx.False(InstallSecurity.IsPackageFullName(new string('a', 128)), "too long");
                AssertEx.True(InstallSecurity.RootNamesPackage(root, name), "folder name is the package");
                AssertEx.True(InstallSecurity.RootNamesPackage(root, name.ToLowerInvariant()), "any case");
                AssertEx.False(InstallSecurity.RootNamesPackage(root, "Other.App_1.0.0.0_x64__8wekyb3d8bbwe"), "another package's broker");
                AssertEx.False(InstallSecurity.RootNamesPackage(root, null), "a broker without package identity");
                AssertEx.True(InstallSecurity.MatchesPackage(root, name, root), "Windows reports this folder");
                AssertEx.True(InstallSecurity.MatchesPackage(@"\\?\D:\WindowsApps\" + name, name, @"\\?\D:\WindowsApps\" + name), "another volume that Windows installed to");
                AssertEx.False(InstallSecurity.MatchesPackage(@"\\?\E:\WindowsApps\" + name, name, root), "a copy on another drive");
                AssertEx.False(InstallSecurity.MatchesPackage(root, name, null), "Windows reports no folder");
                AssertEx.True(InstallSecurity.IsTrustedDriveType(InstallSecurity.DriveFixed), "fixed disk");
                AssertEx.False(InstallSecurity.IsTrustedDriveType(2), "removable");
                AssertEx.False(InstallSecurity.IsTrustedDriveType(4), "network");
                AssertEx.False(InstallSecurity.IsTrustedDriveType(0), "unknown");
            });

            runner.Check("install security: a failed check maps to the starter's reply", delegate
            {
                AssertEx.Equal(ElevationReplyCode.Started, InstallSecurity.ReplyFor(InstallCheck.Trusted, ElevationReplyCode.EngineMissing), "trusted");
                AssertEx.Equal(ElevationReplyCode.AdapterDllMissing, InstallSecurity.ReplyFor(InstallCheck.Missing, ElevationReplyCode.AdapterDllMissing), "missing file");
                foreach (InstallCheck check in new[] { InstallCheck.NotPackageStore, InstallCheck.OutsideRoot, InstallCheck.OwnerUntrusted, InstallCheck.NoDacl, InstallCheck.WritableByOthers, InstallCheck.UnsupportedEntry, InstallCheck.Malformed })
                {
                    AssertEx.Equal(ElevationReplyCode.InstallUntrusted, InstallSecurity.ReplyFor(check, ElevationReplyCode.EngineMissing), check.ToString());
                }
            });

            runner.Check("install security: the starter verifies the install before it duplicates or starts", delegate
            {
                string root = FindWindowsRoot();
                AssertEx.True(root != null, "windows folder");
                string starter = SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2.Elevate", "Program.cs"));
                int server = starter.IndexOf("GetNamedPipeServerProcessId(pipe", StringComparison.Ordinal);
                int brokerImage = starter.IndexOf("SameFinalPath(FinalPathOf(ImagePath(broker))", StringComparison.Ordinal);
                int read = starter.IndexOf("ReadExact(pipe", StringComparison.Ordinal);
                int verify = starter.IndexOf("VerifyInstall(root, packageName, self", StringComparison.Ordinal);
                int duplicate = starter.IndexOf("Duplicate(broker, request.TokenHandle", StringComparison.Ordinal);
                int compare = starter.IndexOf("CompareObjectHandles(tokenHandle, parentHandle)", StringComparison.Ordinal);
                int start = starter.IndexOf("Start(plan,", StringComparison.Ordinal);
                AssertEx.True(server > 0 && brokerImage > server && read > brokerImage, "the pipe server is checked before the request is read");
                int package = starter.IndexOf("InstallSecurity.RootNamesPackage(root, packageName)", StringComparison.Ordinal);
                AssertEx.True(package > brokerImage && read > package, "the broker's package is checked before the request is read");
                AssertEx.True(verify > read && duplicate > verify, "the install is verified before any handle is duplicated");
                AssertEx.Contains(starter, "InstallSecurity.MatchesPackage(root, packageName, FinalPathOf(PackagePathOf(packageName)))", "the root is the package folder Windows reports");
                AssertEx.Contains(starter, "InstallSecurity.IsTrustedDriveType(DriveTypeOf(root))", "fixed disk only");
                AssertEx.Contains(starter, "FileReadAttributes | ReadControl | FileReadData", "read data, so share modes take effect");
                string project = SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2.Elevate", "HotspotShade.WinUI2.Elevate.csproj"));
                AssertEx.Contains(project, "<LinkerArg Include=\"/DEPENDENTLOADFLAG:0x800\" />", "imports load from System32 only");
                AssertEx.True(compare > duplicate && start > compare, "duplicated handles are compared before the engine starts");
                AssertEx.Contains(starter, "FileReadAttributes | ReadControl", "opened for attributes and security only");
                AssertEx.Contains(starter, "FileFlagBackupSemantics", "folders open with backup semantics");
                AssertEx.Contains(starter, "GetFinalPathNameByHandleW", "final paths");
                AssertEx.Contains(starter, "GetSecurityInfo(", "owner and DACL");
                AssertEx.Contains(starter, "InstallSecurity.Evaluate(ownerBytes, daclBytes)", "the pure rule decides");
                AssertEx.Contains(starter, "InstallSecurity.RootFromStarter(selfFinal)", "root from the starter's own final path");
                AssertEx.DoesNotContain(starter, "AppContext.BaseDirectory", "no root from the base directory");
                AssertEx.DoesNotContain(starter, "IsProtectedPackageRoot", "no trust from path text");
                AssertEx.DoesNotContain(starter, "File.Exists", "existence comes from the checked open");
                AssertEx.DoesNotContain(starter, "System.Reflection", "no reflection in the NativeAOT starter");
                AssertEx.DoesNotContain(starter, "Activator.", "no reflection in the NativeAOT starter");
                AssertEx.Contains(starter, "&& written == reply.Length", "the reply write is checked");
                AssertEx.Contains(starter, "SendFailure();", "the watchdog and top-level catch send a failure reply");
                AssertEx.Contains(starter, "CancelSynchronousIo(mainThread)", "the watchdog unblocks a pending read first");
                foreach (string broker in new[] { "ElevatedEngineLauncher.cs", "BrokerService.cs" })
                {
                    string text = SourceText.Read(Path.Combine(root, "src", "HotspotShade.WinUI2.Broker", broker));
                    AssertEx.Contains(text, "InstallRules.IsPackageStorePath(", broker + " keeps the text pre-filter");
                    AssertEx.Contains(text, "A text pre-filter only.", broker + " says it is a pre-filter");
                }
            });
        }

        // An ACL like the one on an installed package folder.
        private static byte[] PackageAcl(params byte[][] extra)
        {
            List<byte[]> aces = new List<byte[]>
            {
                Ace(InstallSecurity.AccessAllowed, ObjectInherit | ContainerInherit, FullControl, InstallSecurity.TrustedInstallerSid),
                Ace(InstallSecurity.AccessAllowed, ObjectInherit | ContainerInherit, InstallSecurity.ReadAndExecute, InstallSecurity.SystemSid),
                Ace(InstallSecurity.AccessAllowed, ObjectInherit | ContainerInherit, InstallSecurity.ReadAndExecute, InstallSecurity.AdministratorsSid),
                Ace(InstallSecurity.AccessAllowed, ObjectInherit | ContainerInherit, InstallSecurity.ReadAndExecute, InstallSecurity.UsersSid),
                Ace(InstallSecurity.AccessAllowed, ObjectInherit | ContainerInherit, InstallSecurity.ReadAndExecute, AllPackagesSid),
                Ace(InstallSecurity.AccessAllowed, ObjectInherit | ContainerInherit, InstallSecurity.ReadAndExecute, PackageSid)
            };
            aces.AddRange(extra);
            return Acl(aces.ToArray());
        }

        private static byte[] Acl(params byte[][] aces)
        {
            int size = 8;
            foreach (byte[] ace in aces)
            {
                size += ace.Length;
            }
            byte[] acl = new byte[size];
            acl[0] = 2;
            acl[2] = (byte)(size & 0xFF);
            acl[3] = (byte)(size >> 8);
            acl[4] = (byte)(aces.Length & 0xFF);
            acl[5] = (byte)(aces.Length >> 8);
            int offset = 8;
            foreach (byte[] ace in aces)
            {
                Array.Copy(ace, 0, acl, offset, ace.Length);
                offset += ace.Length;
            }
            return acl;
        }

        private static byte[] Ace(byte type, byte flags, uint mask, string sid)
        {
            byte[] sidBytes = SidBytes(sid);
            byte[] ace = new byte[8 + sidBytes.Length];
            Header(ace, type, flags);
            WriteUInt32(ace, 4, mask);
            Array.Copy(sidBytes, 0, ace, 8, sidBytes.Length);
            return ace;
        }

        private static byte[] ObjectAce(byte type, uint mask, uint objectFlags, string sid)
        {
            byte[] sidBytes = SidBytes(sid);
            int guids = ((objectFlags & 1) != 0 ? 16 : 0) + ((objectFlags & 2) != 0 ? 16 : 0);
            byte[] ace = new byte[12 + guids + sidBytes.Length];
            Header(ace, type, 0);
            WriteUInt32(ace, 4, mask);
            WriteUInt32(ace, 8, objectFlags);
            for (int index = 0; index < guids; index++)
            {
                ace[12 + index] = 0xAA;
            }
            Array.Copy(sidBytes, 0, ace, 12 + guids, sidBytes.Length);
            return ace;
        }

        private static void Header(byte[] ace, byte type, byte flags)
        {
            ace[0] = type;
            ace[1] = flags;
            ace[2] = (byte)(ace.Length & 0xFF);
            ace[3] = (byte)(ace.Length >> 8);
        }

        // The binary form of a string SID (authority below 2^32).
        private static byte[] SidBytes(string sid)
        {
            string[] parts = sid.Split('-');
            int count = parts.Length - 3;
            byte[] bytes = new byte[8 + (4 * count)];
            bytes[0] = 1;
            bytes[1] = (byte)count;
            ulong authority = ulong.Parse(parts[2], CultureInfo.InvariantCulture);
            for (int index = 0; index < 6; index++)
            {
                bytes[2 + index] = (byte)(authority >> (8 * (5 - index)));
            }
            for (int index = 0; index < count; index++)
            {
                WriteUInt32(bytes, 8 + (4 * index), uint.Parse(parts[3 + index], CultureInfo.InvariantCulture));
            }
            return bytes;
        }

        private static void WriteUInt32(byte[] data, int offset, uint value)
        {
            data[offset] = (byte)value;
            data[offset + 1] = (byte)(value >> 8);
            data[offset + 2] = (byte)(value >> 16);
            data[offset + 3] = (byte)(value >> 24);
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
