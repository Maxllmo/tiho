using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace Tiho.Services;

internal static class WindowTheme
{
    public static void ApplyDarkCaption(Window window)
    {
        var handle = new WindowInteropHelper(window).Handle;
        var enabled = 1;
        if (DwmSetWindowAttribute(handle, 20, ref enabled, sizeof(int)) != 0)
            DwmSetWindowAttribute(handle, 19, ref enabled, sizeof(int));
        var background = 0x0015100D; // Windows COLORREF: #0D1015.
        var foreground = 0x00F8F2ED;
        DwmSetWindowAttribute(handle, 35, ref background, sizeof(int));
        DwmSetWindowAttribute(handle, 36, ref foreground, sizeof(int));
    }
    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr window, int attribute, ref int value, int size);
}
