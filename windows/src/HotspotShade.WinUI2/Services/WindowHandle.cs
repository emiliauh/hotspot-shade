using System;
using System.Runtime.InteropServices;
using Windows.UI.Core;

namespace HotspotShade.WinUI2.Services
{
    // The HWND of the app window. The broker passes it to Windows as the
    // owner of the UAC prompt at Turn on, so Windows shows the prompt in
    // front of the app instead of a flashing taskbar button. The value is
    // used for nothing else.
    public static class WindowHandle
    {
        [ComImport]
        [Guid("45D64A29-A63E-4CB6-B498-5781D298CB4F")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface ICoreWindowInterop
        {
            IntPtr WindowHandle { get; }

            bool MessageHandled { set; }
        }

        public static long Current()
        {
            try
            {
                CoreWindow window = CoreWindow.GetForCurrentThread();
                if (window == null)
                {
                    return 0;
                }
                ICoreWindowInterop interop = (ICoreWindowInterop)(object)window;
                return interop.WindowHandle.ToInt64();
            }
            catch (Exception)
            {
                return 0;
            }
        }
    }
}
