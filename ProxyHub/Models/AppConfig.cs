using System.Text.Json.Serialization;

namespace ProxyHub.Models;

public sealed class AppConfig
{
    public string UpstreamType { get; set; } = "SOCKS5";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 1080;
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public int ListenPort { get; set; } = 3128;
    public bool AutoStartHub { get; set; } = true;
    public bool StartWithWindows { get; set; } = false;
    public bool MinimizeToTray { get; set; } = true;
    public bool PcProxyEnabled { get; set; } = false;
    public bool Ps5ViaLocalHub { get; set; } = false;

    [JsonIgnore]
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Host) && Port is > 0 and <= 65535;
}
