using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ProxyHub.Services;

public sealed class SystemProxyService
{
    private const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private static readonly string SnapshotPath = Path.Combine(ConfigStore.RootDir, "proxy-snapshot.json");

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    public void EnableLocal(int port)
    {
        Directory.CreateDirectory(ConfigStore.RootDir);
        SaveSnapshotIfNeeded();

        using var key = Registry.CurrentUser.OpenSubKey(KeyPath, true)
                        ?? throw new InvalidOperationException("Не удалось открыть настройки прокси Windows.");

        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
        key.SetValue("ProxyServer", $"127.0.0.1:{port}", RegistryValueKind.String);
        key.SetValue("ProxyOverride", "*.ru;*.xn--p1ai;<local>;127.0.0.1;localhost;*.local", RegistryValueKind.String);
        key.SetValue("AutoDetect", 0, RegistryValueKind.DWord);
        try { key.DeleteValue("AutoConfigURL", false); } catch { /* ignore */ }

        Refresh();
    }

    public void Restore()
    {
        if (!File.Exists(SnapshotPath))
        {
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath, true);
            key?.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            Refresh();
            return;
        }

        var snap = System.Text.Json.JsonSerializer.Deserialize<Snapshot>(File.ReadAllText(SnapshotPath));
        using var k = Registry.CurrentUser.OpenSubKey(KeyPath, true);
        if (k is null || snap is null)
            return;

        k.SetValue("ProxyEnable", snap.ProxyEnable, RegistryValueKind.DWord);
        SetOrDelete(k, "ProxyServer", snap.ProxyServer);
        SetOrDelete(k, "ProxyOverride", snap.ProxyOverride);
        SetOrDelete(k, "AutoConfigURL", snap.AutoConfigUrl);
        k.SetValue("AutoDetect", snap.AutoDetect, RegistryValueKind.DWord);
        Refresh();
    }

    public bool IsPointingToUs(int port)
    {
        using var key = Registry.CurrentUser.OpenSubKey(KeyPath, false);
        if (key is null)
            return false;
        var enabled = Convert.ToInt32(key.GetValue("ProxyEnable", 0)) == 1;
        var server = key.GetValue("ProxyServer") as string ?? "";
        return enabled && server.Contains($"127.0.0.1:{port}", StringComparison.OrdinalIgnoreCase);
    }

    private void SaveSnapshotIfNeeded()
    {
        if (File.Exists(SnapshotPath))
            return;

        using var key = Registry.CurrentUser.OpenSubKey(KeyPath, false);
        if (key is null)
            return;

        var snap = new Snapshot
        {
            ProxyEnable = Convert.ToInt32(key.GetValue("ProxyEnable", 0)),
            ProxyServer = key.GetValue("ProxyServer") as string,
            ProxyOverride = key.GetValue("ProxyOverride") as string,
            AutoConfigUrl = key.GetValue("AutoConfigURL") as string,
            AutoDetect = Convert.ToInt32(key.GetValue("AutoDetect", 0))
        };

        File.WriteAllText(SnapshotPath, System.Text.Json.JsonSerializer.Serialize(snap, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }

    public void ForgetSnapshot()
    {
        try { File.Delete(SnapshotPath); } catch { /* ignore */ }
    }

    private static void SetOrDelete(RegistryKey key, string name, string? value)
    {
        if (string.IsNullOrEmpty(value))
            key.DeleteValue(name, false);
        else
            key.SetValue(name, value, RegistryValueKind.String);
    }

    private static void Refresh()
    {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0); // SETTINGS_CHANGED
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0); // REFRESH
    }

    private sealed class Snapshot
    {
        public int ProxyEnable { get; set; }
        public string? ProxyServer { get; set; }
        public string? ProxyOverride { get; set; }
        public string? AutoConfigUrl { get; set; }
        public int AutoDetect { get; set; }
    }
}
