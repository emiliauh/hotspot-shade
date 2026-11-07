using Windows.ApplicationModel.DataTransfer;

namespace HotspotShade.WinUI2.Services
{
    // Copy one text that the person asked for: the pairing code, the failure
    // report, or the diagnostics report. This uses the Windows clipboard
    // only. The texts hold no token, key, or bearer secret.
    public static class ClipboardService
    {
        public static bool TrySetText(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return false;
            }
            try
            {
                DataPackage package = new DataPackage();
                package.SetText(text);
                Clipboard.SetContent(package);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
