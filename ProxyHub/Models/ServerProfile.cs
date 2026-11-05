namespace ProxyHub.Models;

public sealed class ServerProfile
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "Сервер";
    public string Kind { get; set; } = "vpn";
    public string Protocol { get; set; } = "AmneziaWG";
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string WireGuardConfig { get; set; } = "";
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsAmnezia => Protocol.Equals("AmneziaWG", StringComparison.OrdinalIgnoreCase);
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsConfigured => !string.IsNullOrWhiteSpace(Host) && Port is > 0 and <= 65535;
    public override string ToString() => Name;
}
