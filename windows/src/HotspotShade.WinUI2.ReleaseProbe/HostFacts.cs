using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace HotspotShade.WinUI2.ReleaseProbe
{
    internal static class HostFacts
    {
        // The process token check. It is only asked on Windows. An unknown
        // answer stays unknown and becomes a warning, never a claim.
        public static bool TryIsAdministrator(out bool administrator)
        {
            administrator = false;
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return false;
            }
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    if (identity == null)
                    {
                        return false;
                    }
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    administrator = principal.IsInRole(WindowsBuiltInRole.Administrator);
                    return true;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        // One lowercase hex SHA-256 of the file. A read failure returns null so
        // the report says the hash is unavailable instead of inventing one.
        public static string Sha256(string path)
        {
            try
            {
                using (SHA256 algorithm = SHA256.Create())
                using (FileStream stream = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read))
                {
                    byte[] hash = algorithm.ComputeHash(stream);
                    StringBuilder text = new StringBuilder(hash.Length * 2);
                    for (int index = 0; index < hash.Length; index++)
                    {
                        text.Append(hash[index].ToString("x2", CultureInfo.InvariantCulture));
                    }
                    Array.Clear(hash, 0, hash.Length);
                    return text.ToString();
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        // Keep a fixed report field to ASCII and to one bounded line. A long
        // operating system name is trimmed rather than copied whole.
        public static string Sanitize(string value, int maximumLength)
        {
            if (string.IsNullOrEmpty(value) || maximumLength <= 0)
            {
                return "";
            }
            StringBuilder text = new StringBuilder();
            for (int index = 0; index < value.Length && text.Length < maximumLength; index++)
            {
                char character = value[index];
                text.Append(character >= 0x20 && character <= 0x7E ? character : ' ');
            }
            return text.ToString().Trim();
        }
    }
}
