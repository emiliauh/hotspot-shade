using System;

namespace HotspotShade.WinUI2.Core.App
{
    // Where an elevated engine may start from. The engine loads wintun.dll
    // from its own folder, so that folder must not be writable by a standard
    // user. An installed MSIX package lives in a WindowsApps package store,
    // which only the system can change: Program Files\WindowsApps on the
    // system drive, or X:\WindowsApps when apps are installed on another
    // volume. A Visual Studio loose-file deployment lives in a user folder,
    // so it can show the dashboard and pair, but Turn on is refused there.
    public static class InstallRules
    {
        // The check is plain text so that it gives the same answer on every
        // host. The broker and the starter pass absolute paths that Windows
        // reported (the package install folder and the running program).
        public static bool IsProtectedPackageRoot(string root, string programFiles)
        {
            if (string.IsNullOrEmpty(root))
            {
                return false;
            }
            string full = root.Replace('/', '\\').TrimEnd('\\');
            if (full.IndexOf("\\..", StringComparison.Ordinal) >= 0
                || full.IndexOf("\\.\\", StringComparison.Ordinal) >= 0
                || full.IndexOf('~') >= 0)
            {
                return false;
            }
            if (!string.IsNullOrEmpty(programFiles))
            {
                string apps = programFiles.Replace('/', '\\').TrimEnd('\\') + "\\WindowsApps";
                if (apps.Length >= 15 && IsBelow(full, apps))
                {
                    return true;
                }
            }
            // A package store on another volume: X:\WindowsApps\<package>.
            bool drive = full.Length > 3 && char.IsLetter(full[0]) && full[1] == ':' && full[2] == '\\';
            return drive && IsBelow(full, full.Substring(0, 2) + "\\WindowsApps");
        }

        private static bool IsBelow(string full, string folder)
        {
            return full.Length > folder.Length + 1
                && full.StartsWith(folder + "\\", StringComparison.OrdinalIgnoreCase);
        }
    }
}
