using System.Net;
using ProxyHub.Models;

namespace ProxyHub.Services;

public static class AmneziaConfigImporter
{
    public static ServerProfile Parse(string text, string name)
    {
        if (text.Length > 1024 * 1024) throw new InvalidOperationException("Файл конфигурации слишком большой.");
        var sections = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string>? current = null;
        foreach (var raw in text.TrimStart('\uFEFF').Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';')) continue;
            if (line.StartsWith('['))
            {
                if (!line.Equals("[Interface]", StringComparison.OrdinalIgnoreCase) && !line.Equals("[Peer]", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Неизвестная секция конфигурации.");
                if (sections.ContainsKey(line)) throw new InvalidOperationException("Нужен клиентский .conf с одним [Interface] и одним [Peer].");
                current = new(StringComparer.OrdinalIgnoreCase); sections.Add(line, current); continue;
            }
            var pair = line.Split('=', 2);
            if (pair.Length != 2 || current is null) throw new InvalidOperationException("Некорректный формат .conf.");
            current[pair[0].Trim()] = pair[1].Trim();
        }
        if (!sections.TryGetValue("[Interface]", out var iface) || !sections.TryGetValue("[Peer]", out var peer))
            throw new InvalidOperationException("Нужен клиентский .conf AmneziaWG, содержащий [Interface] и [Peer].");
        RequireKey(iface, "PrivateKey"); RequireKey(peer, "PublicKey");
        if (peer.TryGetValue("PresharedKey", out var psk) && psk.Length > 0) RequireKey(peer, "PresharedKey");
        if (iface.TryGetValue("HeaderProtectionKey", out var hpk) && hpk.Length > 0) RequireKey(iface, "HeaderProtectionKey");
        if (!iface.TryGetValue("Address", out var addresses) || addresses.Split(',').Any(s => !ValidClientAddress(s)))
            throw new InvalidOperationException("В .conf отсутствует корректный Address клиента.");
        if (!peer.TryGetValue("Endpoint", out var endpoint) || !Uri.TryCreate("udp://" + endpoint, UriKind.Absolute, out var uri) || uri.Port is <= 0 or > 65535 || string.IsNullOrWhiteSpace(uri.Host))
            throw new InvalidOperationException("В .conf отсутствует Endpoint сервера с портом.");
        return new ServerProfile
        {
            Name = string.IsNullOrWhiteSpace(name) ? "AmneziaWG" : name, Kind = "vpn", Protocol = "AmneziaWG",
            Host = uri.Host.Trim('[', ']'), Port = uri.Port, WireGuardConfig = text
        };
    }

    private static void RequireKey(Dictionary<string, string> section, string name)
    {
        try { if (!section.TryGetValue(name, out var value) || Convert.FromBase64String(value).Length != 32) throw new FormatException(); }
        catch (FormatException) { throw new InvalidOperationException($"В .conf некорректный {name}."); }
    }
    private static bool ValidClientAddress(string value)
    {
        var parts = value.Trim().Split('/');
        return parts.Length == 2 && IPAddress.TryParse(parts[0], out var address) && int.TryParse(parts[1], out var prefix)
            && prefix >= 0 && prefix <= (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
    }
}
