using System.Text.Json;
using ProxyHub.Models;

namespace ProxyHub.Services;

public static class ShareLinkParser
{
    public static IReadOnlyList<ServerProfile> ParseMany(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<ServerProfile>();

        var list = ParseLines(text);
        if (list.Count > 0)
            return list;

        var decoded = TryDecodeText(text.Trim());
        if (!string.IsNullOrWhiteSpace(decoded) && !decoded.Equals(text.Trim(), StringComparison.Ordinal))
            list = ParseLines(decoded);

        if (list.Count == 0)
        {
            var one = TryParseOne(text.Trim());
            if (one is not null)
                list.Add(one);
        }

        return list;
    }

    public static ServerProfile ParseOne(string uri) =>
        TryParseOne(uri) ?? throw new InvalidOperationException("Не удалось разобрать ссылку.");

    public static ServerProfile? TryParseOne(string uri)
    {
        uri = uri.Trim();
        if (uri.Length == 0 || uri.StartsWith('#'))
            return null;

        try
        {
            if (uri.StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
                return ParseVless(uri);
            if (uri.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
                return ParseVmess(uri);
            if (uri.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase))
                return ParseTrojan(uri);
            if (uri.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
                return ParseShadowsocks(uri);
            if (uri.StartsWith("hysteria2://", StringComparison.OrdinalIgnoreCase) ||
                uri.StartsWith("hy2://", StringComparison.OrdinalIgnoreCase))
                return ParseHysteria2(uri);
            if (uri.StartsWith("wireguard://", StringComparison.OrdinalIgnoreCase) ||
                uri.StartsWith("wg://", StringComparison.OrdinalIgnoreCase))
                return ParseWireGuard(uri);
            if (uri.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase) ||
                uri.StartsWith("socks://", StringComparison.OrdinalIgnoreCase))
                return ParseSocks(uri);
            if (uri.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return ParseHttpProxy(uri);
            if (uri.StartsWith("tg://", StringComparison.OrdinalIgnoreCase))
                return ParseTelegram(uri);
        }
        catch
        {
            return null;
        }

        return null;
    }

    private static List<ServerProfile> ParseLines(string text)
    {
        var list = new List<ServerProfile>();
        foreach (var raw in text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            var line = raw.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                continue;
            var profile = TryParseOne(line);
            if (profile is not null)
                list.Add(profile);
        }
        return list;
    }

    private static ServerProfile ParseVless(string uri)
    {
        SplitUri(uri, "vless", out var user, out var host, out var port, out var query, out var fragment);
        var q = ParseQuery(query);
        return new ServerProfile
        {
            Name = NameOr(fragment, host, port),
            Kind = "vpn",
            Protocol = "VLESS",
            Host = host,
            Port = port,
            Uuid = user,
            Username = user,
            Flow = Q(q, "flow"),
            Security = Q(q, "security"),
            Network = Net(Q(q, "type", "network"), "tcp"),
            Path = Q(q, "path"),
            Sni = Q(q, "sni", "peer"),
            HostHeader = Q(q, "host", "authority"),
            Alpn = Q(q, "alpn"),
            Fingerprint = Q(q, "fp", "fingerprint"),
            PublicKey = Q(q, "pbk", "publicKey"),
            ShortId = Q(q, "sid", "shortId"),
            SpiderX = Q(q, "spx"),
            ServiceName = Q(q, "serviceName", "servicename"),
            HeaderType = Q(q, "headerType"),
            Insecure = IsTrue(Q(q, "allowInsecure", "insecure")),
            ShareUri = uri
        };
    }

    private static ServerProfile ParseVmess(string uri)
    {
        var payload = uri["vmess://".Length..];
        var json = Encoding.UTF8.GetString(FromBase64(payload));
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        var host = Str(r, "add");
        var port = Int(r, "port", 443);
        var name = Str(r, "ps");
        var tls = Str(r, "tls");
        return new ServerProfile
        {
            Name = NameOr(name, host, port),
            Kind = "vpn",
            Protocol = "VMess",
            Host = host,
            Port = port,
            Uuid = Str(r, "id"),
            Username = Str(r, "id"),
            Method = Str(r, "scy", "security"),
            Network = Net(Str(r, "net", "type"), "tcp"),
            Path = Str(r, "path"),
            Sni = Str(r, "sni"),
            HostHeader = Str(r, "host"),
            Alpn = Str(r, "alpn"),
            Fingerprint = Str(r, "fp"),
            Security = tls.Length > 0 && !tls.Equals("none", StringComparison.OrdinalIgnoreCase) ? "tls" : "",
            HeaderType = Str(r, "type"),
            Insecure = IsTrue(Str(r, "allowInsecure", "insecure")),
            ShareUri = uri
        };
    }

    private static ServerProfile ParseTrojan(string uri)
    {
        SplitUri(uri, "trojan", out var password, out var host, out var port, out var query, out var fragment);
        var q = ParseQuery(query);
        return new ServerProfile
        {
            Name = NameOr(fragment, host, port),
            Kind = "vpn",
            Protocol = "Trojan",
            Host = host,
            Port = port,
            Password = password,
            Security = Q(q, "security").Length > 0 ? Q(q, "security") : "tls",
            Network = Net(Q(q, "type", "network"), "tcp"),
            Path = Q(q, "path"),
            Sni = Q(q, "sni", "peer"),
            HostHeader = Q(q, "host"),
            Alpn = Q(q, "alpn"),
            Fingerprint = Q(q, "fp", "fingerprint"),
            ServiceName = Q(q, "serviceName", "servicename"),
            HeaderType = Q(q, "headerType"),
            Insecure = IsTrue(Q(q, "allowInsecure", "insecure")),
            ShareUri = uri
        };
    }

    private static ServerProfile ParseShadowsocks(string uri)
    {
        var rest = uri["ss://".Length..];
        SplitFragment(ref rest, out var fragment);

        string method;
        string password;
        string host;
        int port;

        var at = rest.LastIndexOf('@');
        if (at < 0)
        {
            rest = Encoding.UTF8.GetString(FromBase64(rest));
            at = rest.LastIndexOf('@');
        }

        if (at < 0)
            throw new InvalidOperationException("Некорректная ss:// ссылка.");

        var userinfo = rest[..at];
        var hostport = rest[(at + 1)..];
        if (!userinfo.Contains(':', StringComparison.Ordinal))
            userinfo = Encoding.UTF8.GetString(FromBase64(userinfo));

        var colon = userinfo.IndexOf(':');
        if (colon < 0)
            throw new InvalidOperationException("В ss:// нет метода или пароля.");

        method = Uri.UnescapeDataString(userinfo[..colon]);
        password = Uri.UnescapeDataString(userinfo[(colon + 1)..]);
        SplitHostPort(hostport, 8388, out host, out port);

        return new ServerProfile
        {
            Name = NameOr(fragment, host, port),
            Kind = "vpn",
            Protocol = "Shadowsocks",
            Host = host,
            Port = port,
            Method = method,
            Password = password,
            ShareUri = uri
        };
    }

    private static ServerProfile ParseHysteria2(string uri)
    {
        var scheme = uri.StartsWith("hy2://", StringComparison.OrdinalIgnoreCase) ? "hy2" : "hysteria2";
        SplitUri(uri, scheme, out var password, out var host, out var port, out var query, out var fragment);
        var q = ParseQuery(query);
        return new ServerProfile
        {
            Name = NameOr(fragment, host, port),
            Kind = "vpn",
            Protocol = "Hysteria2",
            Host = host,
            Port = port,
            Password = Uri.UnescapeDataString(password),
            Sni = Q(q, "sni"),
            Insecure = IsTrue(Q(q, "insecure", "allowInsecure")),
            Method = Q(q, "obfs"),
            HeaderType = Q(q, "obfs-password", "obfsPassword"),
            ShareUri = uri
        };
    }

    private static ServerProfile ParseWireGuard(string uri)
    {
        var scheme = uri.StartsWith("wg://", StringComparison.OrdinalIgnoreCase) ? "wg" : "wireguard";
        SplitUri(uri, scheme, out var privateKey, out var host, out var port, out var query, out var fragment);
        var q = ParseQuery(query);
        return new ServerProfile
        {
            Name = NameOr(fragment, host, port),
            Kind = "vpn",
            Protocol = "WireGuard",
            Host = host,
            Port = port,
            Password = Uri.UnescapeDataString(privateKey),
            PublicKey = Q(q, "publickey", "publicKey", "peer"),
            LocalAddress = Q(q, "address", "ip"),
            ShareUri = uri
        };
    }

    private static ServerProfile ParseSocks(string uri)
    {
        SplitUri(uri, uri.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase) ? "socks5" : "socks",
            out var userinfo, out var host, out var port, out _, out var fragment);
        SplitUserPass(userinfo, out var user, out var pass);
        return new ServerProfile
        {
            Name = NameOr(fragment, host, port),
            Kind = "proxy",
            Protocol = "SOCKS5",
            Host = host,
            Port = port == 0 ? 1080 : port,
            Username = user,
            Password = pass,
            ShareUri = uri
        };
    }

    private static ServerProfile? ParseHttpProxy(string uri)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var u))
            return null;
        if (u.Host.Length == 0 || u.Port <= 0)
            return null;
        if (LooksLikeWebPage(u))
            return null;

        var user = "";
        var pass = "";
        if (!string.IsNullOrEmpty(u.UserInfo))
            SplitUserPass(u.UserInfo, out user, out pass);

        return new ServerProfile
        {
            Name = NameOr(Uri.UnescapeDataString(u.Fragment.TrimStart('#')), u.Host, u.Port),
            Kind = "proxy",
            Protocol = "HTTP",
            Host = u.Host,
            Port = u.Port,
            Username = user,
            Password = pass,
            ShareUri = uri
        };
    }

    private static ServerProfile? ParseTelegram(string uri)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var u))
            return null;
        var q = ParseQuery(u.Query.TrimStart('?'));
        var host = Q(q, "server", "host");
        var port = int.TryParse(Q(q, "port"), out var p) ? p : 0;
        if (string.IsNullOrWhiteSpace(host) || port <= 0)
            return null;

        var isHttp = u.Host.Equals("http", StringComparison.OrdinalIgnoreCase);
        return new ServerProfile
        {
            Name = NameOr(Q(q, "remarks", "name"), host, port),
            Kind = "proxy",
            Protocol = isHttp ? "HTTP" : "SOCKS5",
            Host = host,
            Port = port,
            Username = Q(q, "user", "username"),
            Password = Q(q, "pass", "password"),
            ShareUri = uri
        };
    }

    private static bool LooksLikeWebPage(Uri u)
    {
        if (u.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) && u.Port == 443)
            return true;
        if (u.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) && u.Port == 80)
            return true;
        return u.AbsolutePath.Length > 1;
    }

    private static void SplitUri(string uri, string scheme, out string user, out string host, out int port, out string query, out string fragment)
    {
        var rest = uri[(scheme.Length + 3)..];
        SplitFragment(ref rest, out fragment);
        query = "";
        var qi = rest.IndexOf('?');
        if (qi >= 0)
        {
            query = rest[(qi + 1)..];
            rest = rest[..qi];
        }

        var at = rest.LastIndexOf('@');
        if (at >= 0)
        {
            user = Uri.UnescapeDataString(rest[..at]);
            rest = rest[(at + 1)..];
        }
        else
        {
            user = "";
        }

        SplitHostPort(rest, 443, out host, out port);
    }

    private static void SplitFragment(ref string rest, out string fragment)
    {
        var hash = rest.IndexOf('#');
        if (hash < 0)
        {
            fragment = "";
            return;
        }

        fragment = Uri.UnescapeDataString(rest[(hash + 1)..]);
        rest = rest[..hash];
    }

    private static void SplitHostPort(string value, int fallback, out string host, out int port)
    {
        value = value.Trim();
        if (value.StartsWith('['))
        {
            var rb = value.IndexOf(']');
            host = value[1..rb];
            port = fallback;
            if (rb + 2 < value.Length && value[rb + 1] == ':')
                port = int.Parse(value[(rb + 2)..]);
            return;
        }

        var idx = value.LastIndexOf(':');
        if (idx > 0 && int.TryParse(value[(idx + 1)..], out var p) && p is > 0 and <= 65535)
        {
            host = value[..idx];
            port = p;
            return;
        }

        host = value;
        port = fallback;
    }

    private static void SplitUserPass(string userinfo, out string user, out string pass)
    {
        userinfo = Uri.UnescapeDataString(userinfo ?? "");
        var colon = userinfo.IndexOf(':');
        if (colon < 0)
        {
            user = userinfo;
            pass = "";
            return;
        }

        user = userinfo[..colon];
        pass = userinfo[(colon + 1)..];
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query))
            return map;

        foreach (var part in query.Split('&'))
        {
            if (part.Length == 0)
                continue;
            var eq = part.IndexOf('=');
            if (eq < 0)
            {
                map[Uri.UnescapeDataString(part)] = "";
                continue;
            }

            map[Uri.UnescapeDataString(part[..eq])] = Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' '));
        }

        return map;
    }

    private static string Q(Dictionary<string, string> q, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (q.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
                return value;
        }
        return "";
    }

    private static string Net(string value, string fallback)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Equals("none", StringComparison.OrdinalIgnoreCase))
            return fallback;
        return value.ToLowerInvariant() switch
        {
            "websocket" => "ws",
            "h2" => "http",
            "raw" => "tcp",
            _ => value
        };
    }

    private static string NameOr(string name, string host, int port)
        => string.IsNullOrWhiteSpace(name) ? $"{host}:{port}" : name.Trim();

    private static bool IsTrue(string value)
        => value is "1" or "true" or "yes" or "on";

    private static string Str(JsonElement r, params string[] names)
    {
        foreach (var name in names)
        {
            if (!r.TryGetProperty(name, out var el))
                continue;
            return el.ValueKind switch
            {
                JsonValueKind.String => el.GetString() ?? "",
                JsonValueKind.Number => el.ToString(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => el.ToString()
            };
        }
        return "";
    }

    private static int Int(JsonElement r, string name, int fallback)
        => int.TryParse(Str(r, name), out var n) && n is > 0 and <= 65535 ? n : fallback;

    private static string? TryDecodeText(string text)
    {
        try
        {
            var bytes = FromBase64(text.Replace("\r", "").Replace("\n", "").Replace(" ", ""));
            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return null;
        }
    }

    public static byte[] FromBase64(string value)
    {
        var s = value.Trim().Replace('-', '+').Replace('_', '/').TrimEnd('=');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }
}
