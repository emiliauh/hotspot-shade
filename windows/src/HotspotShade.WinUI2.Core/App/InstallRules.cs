using System;

namespace HotspotShade.WinUI2.Core.App
{
    // Where an elevated engine may start from. The engine loads wintun.dll
    // from its own folder, so that folder must not be writable by a standard
    // user. An installed MSIX package lives in a WindowsApps package store:
    // Program Files\WindowsApps on the system drive, or X:\WindowsApps when
    // apps are installed on another volume. A Visual Studio loose-file
    // deployment lives in a user folder, so it can show the dashboard and
    // pair, but Turn on is refused there.
    //
    // This text rule is only a location rule. The path text alone proves
    // nothing about who can change the folder (a standard user can create
    // D:\WindowsApps on many volumes), so:
    // - The broker and the window use it only as a quick pre-filter, to show
    //   Turn on as unavailable early with a plain reason.
    // - The elevated starter applies it to the final path that Windows
    //   resolves from an open handle, and then requires the owner and DACL
    //   checks in InstallSecurity before it trusts the folder.
    public static class InstallRules
    {
        // True when the path text names a folder below a WindowsApps package
        // store. The check is plain text so that it gives the same answer on
        // every host.
        public static bool IsPackageStorePath(string root, string programFiles)
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
            // The starter trusts it only after the owner and DACL checks.
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
