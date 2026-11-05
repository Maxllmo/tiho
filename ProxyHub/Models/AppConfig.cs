namespace ProxyHub.Models;

public sealed class AppConfig
{
    public List<ServerProfile> Profiles { get; set; } = new();
    public string ActiveProfileId { get; set; } = "";
    public bool AutoConnect { get; set; } = true;
    public bool StartWithWindows { get; set; } = true;
    public bool MinimizeToTray { get; set; } = true;
    public bool BypassRussia { get; set; } = true;
    public List<string> ExcludedApps { get; set; } = new();
    public List<string> DirectDomains { get; set; } = new();
    [System.Text.Json.Serialization.JsonIgnore]
    public ServerProfile? ActiveProfile => Profiles.FirstOrDefault(p => p.Id == ActiveProfileId) ?? Profiles.FirstOrDefault();
}
