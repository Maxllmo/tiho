using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;
using System.Windows.Media;

namespace ProxyHub.Models;

public sealed class ServerProfile
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
    public string Name { get; set; } = "Новый сервер";
    public string Kind { get; set; } = "proxy";
    public string Protocol { get; set; } = "SOCKS5";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 1080;
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Uuid { get; set; } = "";
    public string Flow { get; set; } = "";
    public string Security { get; set; } = "";
    public string Network { get; set; } = "tcp";
    public string Path { get; set; } = "";
    public string Sni { get; set; } = "";
    public string HostHeader { get; set; } = "";
    public string Alpn { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public string ShortId { get; set; } = "";
    public string SpiderX { get; set; } = "";
    public string ServiceName { get; set; } = "";
    public string Method { get; set; } = "";
    public string HeaderType { get; set; } = "";
    public string LocalAddress { get; set; } = "";
    public bool Insecure { get; set; }
    public string ShareUri { get; set; } = "";
    public string SubscriptionUrl { get; set; } = "";
    public int? LastPingMs { get; set; }

    [JsonIgnore]
    public bool IsVpn => Kind.Equals("vpn", StringComparison.OrdinalIgnoreCase);

    [JsonIgnore]
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Host) && Port is > 0 and <= 65535;
}

public sealed class Subscription
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Name { get; set; } = "Подписка";
    public string Url { get; set; } = "";
    public DateTimeOffset? LastUpdated { get; set; }
}

public sealed class ProfileVm : INotifyPropertyChanged
{
    public ServerProfile Model { get; }

    public ProfileVm(ServerProfile model) => Model = model;

    public string Id => Model.Id;
    public string Name => string.IsNullOrWhiteSpace(Model.Name) ? $"{Model.Host}:{Model.Port}" : Model.Name;
    public string Subtitle => $"{Model.Protocol}  {Model.Host}:{Model.Port}";
    public string KindLabel => Model.IsVpn ? "VPN" : "Прокси";

    private bool _isActive;
    public bool IsActive
    {
        get => _isActive;
        set
        {
            if (_isActive == value) return;
            _isActive = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(StatusBrush));
        }
    }

    private int? _pingMs;
    private bool _pingFailed;

    public int? PingMs
    {
        get => _pingMs;
        set
        {
            _pingMs = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(PingText));
            OnPropertyChanged(nameof(PingBrush));
        }
    }

    public bool PingFailed
    {
        get => _pingFailed;
        set
        {
            _pingFailed = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(PingText));
            OnPropertyChanged(nameof(PingBrush));
        }
    }

    public string PingText =>
        PingFailed ? "timeout" : PingMs is int ms ? $"{ms} ms" : "—";

    public Brush StatusBrush =>
        IsActive ? Frozen("#3ECF8E") : Model.IsVpn ? Frozen("#4BA3F5") : Frozen("#8A9BB5");

    public Brush PingBrush
    {
        get
        {
            if (PingFailed) return Frozen("#F0617D");
            if (PingMs is null) return Frozen("#8A9BB5");
            if (PingMs <= 180) return Frozen("#3ECF8E");
            if (PingMs <= 450) return Frozen("#F0B429");
            return Frozen("#F0617D");
        }
    }

    public void RefreshLabels()
    {
        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(Subtitle));
        OnPropertyChanged(nameof(KindLabel));
        OnPropertyChanged(nameof(StatusBrush));
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private static SolidColorBrush Frozen(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)!);
        if (brush.CanFreeze)
            brush.Freeze();
        return brush;
    }
}
