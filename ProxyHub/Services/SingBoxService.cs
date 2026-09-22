using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using ProxyHub.Models;

namespace ProxyHub.Services;

public sealed class SingBoxService : IDisposable
{
    public static string CoreDir { get; } = Path.Combine(ConfigStore.RootDir, "core");
    public static string ExePath => Path.Combine(CoreDir, "sing-box.exe");

    private Process? _process;
    private string? _activeId;

    public bool IsRunning => _process is { HasExited: false };
    public int SocksPort { get; private set; }
    public string? ActiveProfileId => IsRunning ? _activeId : null;

    public async Task StartAsync(ServerProfile profile, LogService log, CancellationToken ct)
    {
        if (IsRunning && _activeId == profile.Id && SocksPort > 0)
            return;

        await StopAsync();
        await EnsureCoreAsync(log, ct);

        var port = GetFreePort();
        Directory.CreateDirectory(CoreDir);
        var configPath = Path.Combine(CoreDir, "config.json");
        File.WriteAllText(configPath, SingBoxConfig.Build(profile, port));

        var psi = new ProcessStartInfo
        {
            FileName = ExePath,
            Arguments = $"run -c \"{configPath}\"",
            WorkingDirectory = CoreDir,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var errors = new StringBuilder();
        process.OutputDataReceived += (_, e) => { if (!string.IsNullOrEmpty(e.Data)) log.Sys("VPN: " + e.Data); };
        process.ErrorDataReceived += (_, e) =>
        {
            if (string.IsNullOrEmpty(e.Data)) return;
            errors.AppendLine(e.Data);
            log.Error("VPN", e.Data);
        };

        if (!process.Start())
            throw new InvalidOperationException("Не удалось запустить sing-box.");

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        _process = process;
        _activeId = profile.Id;
        SocksPort = port;

        var deadline = DateTime.UtcNow.AddSeconds(8);
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            if (process.HasExited)
            {
                _process = null;
                SocksPort = 0;
                _activeId = null;
                var detail = errors.ToString().Trim();
                throw new InvalidOperationException(
                    string.IsNullOrEmpty(detail)
                        ? $"sing-box завершился сразу (код {process.ExitCode})."
                        : detail);
            }

            if (await PortOpenAsync(port, ct))
            {
                log.Sys($"VPN {profile.Name}: sing-box слушает 127.0.0.1:{port}");
                return;
            }

            await Task.Delay(150, ct);
        }

        await StopAsync();
        throw new InvalidOperationException("sing-box не открыл локальный SOCKS за 8 секунд.");
    }

    public async Task StopAsync()
    {
        var process = _process;
        _process = null;
        SocksPort = 0;
        _activeId = null;
        if (process is null)
            return;

        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
        catch
        {
            // ignored
        }

        try { process.Dispose(); } catch { /* ignored */ }
    }

    public async Task EnsureCoreAsync(LogService log, CancellationToken ct)
    {
        if (File.Exists(ExePath))
            return;

        Directory.CreateDirectory(CoreDir);
        log.Sys("Скачиваю ядро sing-box (нужно для VPN-ссылок как в HAPP)...");

        var zipPath = Path.Combine(CoreDir, "sing-box.zip");
        var url = await ResolveDownloadUrlAsync(ct);
        using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(3) })
        {
            http.DefaultRequestHeaders.UserAgent.ParseAdd("ProxyHub/1.1");
            var bytes = await http.GetByteArrayAsync(url, ct);
            await File.WriteAllBytesAsync(zipPath, bytes, ct);
        }

        using (var zip = ZipFile.OpenRead(zipPath))
        {
            var entry = zip.Entries.FirstOrDefault(e =>
                e.Name.Equals("sing-box.exe", StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidOperationException("В архиве sing-box нет sing-box.exe.");
            entry.ExtractToFile(ExePath, overwrite: true);
        }

        try { File.Delete(zipPath); } catch { /* ignore */ }
        log.Sys("Ядро sing-box установлено.");
    }

    private static async Task<string> ResolveDownloadUrlAsync(CancellationToken ct)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("ProxyHub/1.1");
            http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            var json = await http.GetStringAsync("https://api.github.com/repos/SagerNet/sing-box/releases/latest", ct);
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            foreach (var asset in doc.RootElement.GetProperty("assets").EnumerateArray())
            {
                var name = asset.GetProperty("name").GetString() ?? "";
                if (name.Contains("windows-amd64", StringComparison.OrdinalIgnoreCase) &&
                    name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) &&
                    !name.Contains("legacy", StringComparison.OrdinalIgnoreCase))
                    return asset.GetProperty("browser_download_url").GetString()
                           ?? throw new InvalidOperationException("Нет URL загрузки sing-box.");
            }
        }
        catch
        {
            // fallback below
        }

        return "https://github.com/SagerNet/sing-box/releases/download/v1.12.8/sing-box-1.12.8-windows-amd64.zip";
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static async Task<bool> PortOpenAsync(int port, CancellationToken ct)
    {
        try
        {
            using var tcp = new TcpClient();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(400));
            await tcp.ConnectAsync("127.0.0.1", port, timeout.Token);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        try { StopAsync().GetAwaiter().GetResult(); } catch { /* ignore */ }
    }
}

internal static class SingBoxConfig
{
    public static string Build(ServerProfile profile, int listenPort)
    {
        var root = new JsonObject
        {
            ["log"] = new JsonObject { ["level"] = "warn" },
            ["inbounds"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "mixed",
                    ["tag"] = "in",
                    ["listen"] = "127.0.0.1",
                    ["listen_port"] = listenPort
                }
            },
            ["outbounds"] = new JsonArray
            {
                BuildOutbound(profile),
                new JsonObject { ["type"] = "direct", ["tag"] = "direct" }
            }
        };

        return root.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    }

    private static JsonObject BuildOutbound(ServerProfile p)
    {
        var proto = p.Protocol.Trim();
        if (proto.Equals("VLESS", StringComparison.OrdinalIgnoreCase))
            return Vless(p);
        if (proto.Equals("VMess", StringComparison.OrdinalIgnoreCase))
            return Vmess(p);
        if (proto.Equals("Trojan", StringComparison.OrdinalIgnoreCase))
            return Trojan(p);
        if (proto.Equals("Shadowsocks", StringComparison.OrdinalIgnoreCase) || proto.Equals("SS", StringComparison.OrdinalIgnoreCase))
            return Shadowsocks(p);
        if (proto.Equals("Hysteria2", StringComparison.OrdinalIgnoreCase) || proto.Equals("hy2", StringComparison.OrdinalIgnoreCase))
            return Hysteria2(p);
        if (proto.Equals("WireGuard", StringComparison.OrdinalIgnoreCase))
            return WireGuard(p);
        if (proto.Equals("HTTP", StringComparison.OrdinalIgnoreCase))
            return Http(p);
        return Socks(p);
    }

    private static JsonObject Vless(ServerProfile p)
    {
        var o = new JsonObject
        {
            ["type"] = "vless",
            ["tag"] = "proxy",
            ["server"] = p.Host,
            ["server_port"] = p.Port,
            ["uuid"] = First(p.Uuid, p.Username)
        };
        if (!string.IsNullOrWhiteSpace(p.Flow))
            o["flow"] = p.Flow;
        AttachTls(o, p, defaultTls: HasTls(p));
        AttachTransport(o, p);
        return o;
    }

    private static JsonObject Vmess(ServerProfile p)
    {
        var o = new JsonObject
        {
            ["type"] = "vmess",
            ["tag"] = "proxy",
            ["server"] = p.Host,
            ["server_port"] = p.Port,
            ["uuid"] = First(p.Uuid, p.Username),
            ["security"] = string.IsNullOrWhiteSpace(p.Method) ? "auto" : p.Method,
            ["alter_id"] = 0
        };
        AttachTls(o, p, defaultTls: HasTls(p));
        AttachTransport(o, p);
        return o;
    }

    private static JsonObject Trojan(ServerProfile p)
    {
        var o = new JsonObject
        {
            ["type"] = "trojan",
            ["tag"] = "proxy",
            ["server"] = p.Host,
            ["server_port"] = p.Port,
            ["password"] = p.Password
        };
        AttachTls(o, p, defaultTls: true);
        AttachTransport(o, p);
        return o;
    }

    private static JsonObject Shadowsocks(ServerProfile p)
    {
        return new JsonObject
        {
            ["type"] = "shadowsocks",
            ["tag"] = "proxy",
            ["server"] = p.Host,
            ["server_port"] = p.Port,
            ["method"] = string.IsNullOrWhiteSpace(p.Method) ? "aes-256-gcm" : p.Method,
            ["password"] = p.Password
        };
    }

    private static JsonObject Hysteria2(ServerProfile p)
    {
        var o = new JsonObject
        {
            ["type"] = "hysteria2",
            ["tag"] = "proxy",
            ["server"] = p.Host,
            ["server_port"] = p.Port,
            ["password"] = p.Password
        };
        if (p.Method.Equals("salamander", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(p.HeaderType))
        {
            o["obfs"] = new JsonObject
            {
                ["type"] = "salamander",
                ["password"] = p.HeaderType
            };
        }
        AttachTls(o, p, defaultTls: true);
        return o;
    }

    private static JsonObject WireGuard(ServerProfile p)
    {
        var addresses = string.IsNullOrWhiteSpace(p.LocalAddress)
            ? new[] { "10.0.0.2/32" }
            : p.LocalAddress.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var local = new JsonArray();
        foreach (var address in addresses)
            local.Add(address);

        return new JsonObject
        {
            ["type"] = "wireguard",
            ["tag"] = "proxy",
            ["private_key"] = p.Password,
            ["peer_public_key"] = p.PublicKey,
            ["local_address"] = local,
            ["server"] = p.Host,
            ["server_port"] = p.Port
        };
    }

    private static JsonObject Socks(ServerProfile p)
    {
        var o = new JsonObject
        {
            ["type"] = "socks",
            ["tag"] = "proxy",
            ["server"] = p.Host,
            ["server_port"] = p.Port,
            ["version"] = "5"
        };
        if (!string.IsNullOrEmpty(p.Username))
        {
            o["username"] = p.Username;
            o["password"] = p.Password;
        }
        return o;
    }

    private static JsonObject Http(ServerProfile p)
    {
        var o = new JsonObject
        {
            ["type"] = "http",
            ["tag"] = "proxy",
            ["server"] = p.Host,
            ["server_port"] = p.Port
        };
        if (!string.IsNullOrEmpty(p.Username))
        {
            o["username"] = p.Username;
            o["password"] = p.Password;
        }
        return o;
    }

    private static void AttachTls(JsonObject outbound, ServerProfile p, bool defaultTls)
    {
        var security = (p.Security ?? "").Trim().ToLowerInvariant();
        var reality = security == "reality" || !string.IsNullOrWhiteSpace(p.PublicKey);
        var tlsOn = defaultTls || security is "tls" or "reality" || reality;
        if (!tlsOn || security is "none" or "0")
            return;

        var tls = new JsonObject
        {
            ["enabled"] = true,
            ["insecure"] = p.Insecure
        };
        var sni = First(p.Sni, p.HostHeader);
        if (!string.IsNullOrWhiteSpace(sni))
            tls["server_name"] = sni;
            if (!string.IsNullOrWhiteSpace(p.Alpn))
            {
                var alpn = new JsonArray();
                foreach (var item in p.Alpn.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    alpn.Add(item);
                tls["alpn"] = alpn;
            }
        if (!string.IsNullOrWhiteSpace(p.Fingerprint))
        {
            tls["utls"] = new JsonObject
            {
                ["enabled"] = true,
                ["fingerprint"] = p.Fingerprint
            };
        }
        if (reality)
        {
            var realityObj = new JsonObject { ["enabled"] = true };
            if (!string.IsNullOrWhiteSpace(p.PublicKey))
                realityObj["public_key"] = p.PublicKey;
            if (!string.IsNullOrWhiteSpace(p.ShortId))
                realityObj["short_id"] = p.ShortId;
            tls["reality"] = realityObj;
        }

        outbound["tls"] = tls;
    }

    private static void AttachTransport(JsonObject outbound, ServerProfile p)
    {
        var net = (p.Network ?? "tcp").Trim().ToLowerInvariant();
        if (net is "" or "tcp" or "raw")
        {
            if (p.HeaderType.Equals("http", StringComparison.OrdinalIgnoreCase))
            {
                outbound["transport"] = new JsonObject { ["type"] = "http" };
            }
            return;
        }

        var transport = new JsonObject();
        if (net is "ws" or "websocket")
        {
            transport["type"] = "ws";
            if (!string.IsNullOrWhiteSpace(p.Path))
                transport["path"] = p.Path;
            if (!string.IsNullOrWhiteSpace(p.HostHeader))
                transport["headers"] = new JsonObject { ["Host"] = p.HostHeader };
        }
        else if (net is "grpc")
        {
            transport["type"] = "grpc";
            if (!string.IsNullOrWhiteSpace(p.ServiceName))
                transport["service_name"] = p.ServiceName;
        }
        else if (net is "http" or "h2")
        {
            transport["type"] = "http";
            if (!string.IsNullOrWhiteSpace(p.Path))
                transport["path"] = p.Path;
            if (!string.IsNullOrWhiteSpace(p.HostHeader))
                transport["host"] = new JsonArray(p.HostHeader);
        }
        else if (net is "httpupgrade")
        {
            transport["type"] = "httpupgrade";
            if (!string.IsNullOrWhiteSpace(p.Path))
                transport["path"] = p.Path;
            if (!string.IsNullOrWhiteSpace(p.HostHeader))
                transport["host"] = p.HostHeader;
        }
        else
        {
            return;
        }

        outbound["transport"] = transport;
    }

    private static bool HasTls(ServerProfile p)
    {
        var security = (p.Security ?? "").Trim();
        return security.Equals("tls", StringComparison.OrdinalIgnoreCase)
               || security.Equals("reality", StringComparison.OrdinalIgnoreCase)
               || !string.IsNullOrWhiteSpace(p.PublicKey)
               || !string.IsNullOrWhiteSpace(p.Sni);
    }

    private static string First(params string[] values)
        => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? "";
}
