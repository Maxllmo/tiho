using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using ProxyHub.Models;

namespace ProxyHub.Services;

public static class ConfigStore
{
    public static string RootDir { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ProxyHub");

    public static string LogsDir => Path.Combine(RootDir, "logs");

    private static readonly string ConfigPath = Path.Combine(RootDir, "config.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static AppConfig Load()
    {
        Directory.CreateDirectory(RootDir);
        Directory.CreateDirectory(LogsDir);
        if (!File.Exists(ConfigPath))
            return new AppConfig();

        try
        {
            var json = File.ReadAllText(ConfigPath);
            var cfg = JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();
            if (cfg.MigrateLegacyIfNeeded())
                Save(cfg);
            return cfg;
        }
        catch
        {
            return new AppConfig();
        }
    }

    public static void Save(AppConfig config)
    {
        Directory.CreateDirectory(RootDir);
        File.WriteAllText(ConfigPath, JsonSerializer.Serialize(config, JsonOptions));
    }
}

public static class BypassRules
{
    private static readonly IdnMapping Idn = new();

    public static bool ShouldBypass(string host, out string reason)
    {
        reason = "";
        if (string.IsNullOrWhiteSpace(host))
        {
            reason = "пустой хост";
            return true;
        }

        host = host.Trim().TrimEnd('.').ToLowerInvariant();

        if (host is "localhost" or "127.0.0.1" or "::1" or "0:0:0:0:0:0:0:1")
        {
            reason = "localhost";
            return true;
        }

        if (IPAddress.TryParse(host, out var ip))
        {
            if (IPAddress.IsLoopback(ip) || IsPrivate(ip))
            {
                reason = "локальная сеть";
                return true;
            }

            return false;
        }

        string ascii;
        try
        {
            ascii = Idn.GetAscii(host);
        }
        catch
        {
            ascii = host;
        }

        if (ascii.EndsWith(".ru", StringComparison.Ordinal) || ascii == "ru")
        {
            reason = "домен .ru";
            return true;
        }

        if (ascii.EndsWith(".xn--p1ai", StringComparison.Ordinal) || ascii == "xn--p1ai"
            || host.EndsWith(".рф", StringComparison.Ordinal) || host == "рф")
        {
            reason = "домен .рф";
            return true;
        }

        return false;
    }

    private static bool IsPrivate(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal;

        var b = ip.GetAddressBytes();
        return b[0] == 10
               || b[0] == 127
               || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
               || (b[0] == 192 && b[1] == 168)
               || (b[0] == 169 && b[1] == 254);
    }
}

public static class LanInfo
{
    public static IReadOnlyList<string> GetIpv4Addresses()
    {
        try
        {
            return Dns.GetHostEntry(Dns.GetHostName())
                .AddressList
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))
                .Select(a => a.ToString())
                .Distinct()
                .ToList();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    public static string PrimaryIpv4() => GetIpv4Addresses().FirstOrDefault() ?? "127.0.0.1";
}

public static class StartupService
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "ProxyHub";

    public static void SetEnabled(bool enabled)
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunKey, true);
        if (key is null)
            return;

        if (!enabled)
        {
            key.DeleteValue(ValueName, false);
            return;
        }

        var path = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(path))
            return;

        key.SetValue(ValueName, $"\"{path}\"");
    }
}
