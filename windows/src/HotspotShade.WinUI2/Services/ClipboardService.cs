using Windows.ApplicationModel.DataTransfer;

namespace HotspotShade.WinUI2.Services
{
    // Copy one local simulated text. This uses the Windows clipboard only. It
    // opens no connection and needs no capability.
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
