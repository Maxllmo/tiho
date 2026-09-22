using System.Text.Json.Serialization;

namespace ProxyHub.Models;

public sealed class AppConfig
{
    public List<ServerProfile> Profiles { get; set; } = new();
    public List<Subscription> Subscriptions { get; set; } = new();
    public string ActiveProfileId { get; set; } = "";

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
    public ServerProfile? ActiveProfile =>
        Profiles.FirstOrDefault(p => p.Id == ActiveProfileId) ?? Profiles.FirstOrDefault();

    [JsonIgnore]
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Host) && Port is > 0 and <= 65535;

    public bool MigrateLegacyIfNeeded()
    {
        if (Profiles.Count > 0)
            return false;
        if (string.IsNullOrWhiteSpace(Host) || Port is <= 0 or > 65535)
            return false;

        var profile = new ServerProfile
        {
            Name = "Amnezia",
            Kind = "proxy",
            Protocol = UpstreamType.Equals("HTTP", StringComparison.OrdinalIgnoreCase) ? "HTTP" : "SOCKS5",
            Host = Host.Trim(),
            Port = Port,
            Username = Username ?? "",
            Password = Password ?? ""
        };
        Profiles.Add(profile);
        ActiveProfileId = profile.Id;
        return true;
    }

    public void SyncLiveFromActive(int? vpnSocksPort = null)
    {
        var profile = ActiveProfile;
        if (profile is null)
        {
            Host = "";
            Username = "";
            Password = "";
            return;
        }

        if (profile.IsVpn)
        {
            if (vpnSocksPort is > 0 and <= 65535)
            {
                UpstreamType = "SOCKS5";
                Host = "127.0.0.1";
                Port = vpnSocksPort.Value;
                Username = "";
                Password = "";
            }
            else
            {
                Host = "";
                Username = "";
                Password = "";
            }
            return;
        }

        UpstreamType = profile.Protocol.Equals("HTTP", StringComparison.OrdinalIgnoreCase) ? "HTTP" : "SOCKS5";
        Host = profile.Host?.Trim() ?? "";
        Port = profile.Port;
        Username = profile.Username ?? "";
        Password = profile.Password ?? "";
    }
}
