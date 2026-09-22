using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyHub.Models;

namespace ProxyHub.Services;

public sealed class LocalHttpProxy
{
    private readonly LogService _log;
    private readonly HubStats _stats;
    private readonly Func<AppConfig> _config;
    private CancellationTokenSource? _cts;
    private TcpListener? _listener;
    private Task? _acceptLoop;

    public bool IsRunning { get; private set; }
    public int BoundPort { get; private set; }

    public LocalHttpProxy(LogService log, HubStats stats, Func<AppConfig> config)
    {
        _log = log;
        _stats = stats;
        _config = config;
    }

    public async Task StartAsync(int port)
    {
        if (IsRunning)
            return;

        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Any, port);
        _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _listener.Start(512);
        BoundPort = ((IPEndPoint)_listener.LocalEndpoint).Port;
        IsRunning = true;
        var ct = _cts.Token;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(ct), ct);
        _log.Sys($"Локальный HTTP-прокси слушает 0.0.0.0:{BoundPort}");
        await Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        if (!IsRunning)
            return;

        IsRunning = false;
        try { _cts?.Cancel(); } catch { /* ignore */ }
        try { _listener?.Stop(); } catch { /* ignore */ }
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop; } catch { /* ignore */ }
        }
        _cts?.Dispose();
        _cts = null;
        _listener = null;
        _acceptLoop = null;
        _log.Sys("Локальный HTTP-прокси остановлен.");
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener is not null)
        {
            TcpClient? client = null;
            try
            {
                client = await _listener.AcceptTcpClientAsync(ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                _log.Error("SYS", $"Accept: {ex.Message}");
                continue;
            }

            _ = Task.Run(() => HandleClientAsync(client, ct), ct);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        client.NoDelay = true;
        client.ReceiveTimeout = 120_000;
        client.SendTimeout = 120_000;
        Interlocked.Increment(ref _stats.Active);
        Interlocked.Increment(ref _stats.Requests);

        var remote = (client.Client.RemoteEndPoint as IPEndPoint);
        var source = IsLocal(remote) ? "PC" : "LAN";
        var sourceLabel = source == "PC" ? "PC" : (remote?.Address.ToString() ?? "LAN");

        try
        {
            using var clientStream = client.GetStream();
            var (headerBytes, leftover) = await ReadHeadersAsync(clientStream, ct);
            if (headerBytes.Length == 0)
                return;

            var parsed = HttpProxyRequest.Parse(headerBytes);
            var cfg = _config();
            var bypass = BypassRules.ShouldBypass(parsed.Host, out var bypassReason);
            var via = bypass ? $"DIRECT ({bypassReason})" : cfg.UpstreamType;
            var httpForward = !bypass
                && !parsed.IsConnect
                && cfg.UpstreamType.Equals("HTTP", StringComparison.OrdinalIgnoreCase);

            try
            {
                Stream remoteStream;
                try
                {
                    remoteStream = httpForward
                        ? await UpstreamClient.ConnectHttpProxyAsync(cfg, ct)
                        : await UpstreamClient.OpenAsync(cfg, parsed.Host, parsed.Port, bypass, ct);
                }
                catch (HttpConnectDeniedException ex) when (
                    parsed.IsConnect
                    && parsed.Port != 443
                    && ex.StatusCode is 403 or 405 or 501)
                {
                    via = $"DIRECT (Squid не туннелит порт {parsed.Port})";
                    remoteStream = await UpstreamClient.ConnectDirectAsync(parsed.Host, parsed.Port, ct);
                }

                await using (remoteStream)
                {
                    if (parsed.IsConnect)
                    {
                        var ok = "HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray();
                        await clientStream.WriteAsync(ok, ct);
                        if (leftover.Length > 0)
                            await remoteStream.WriteAsync(leftover, ct);
                        if (via.StartsWith("DIRECT", StringComparison.Ordinal))
                            _log.Bypass(sourceLabel, $"CONNECT {parsed.Host}:{parsed.Port}  {via}");
                        else
                            _log.Info(sourceLabel, $"CONNECT {parsed.Host}:{parsed.Port}  {via}");

                        await PipeAsync(clientStream, remoteStream, ct);
                    }
                    else
                    {
                        var forwarded = httpForward ? parsed.BuildProxyRequest(cfg) : parsed.BuildOriginRequest();
                        await remoteStream.WriteAsync(forwarded, ct);
                        if (leftover.Length > 0)
                            await remoteStream.WriteAsync(leftover, ct);

                        if (bypass)
                            _log.Bypass(sourceLabel, $"{parsed.Method} {parsed.Host}:{parsed.Port}  {via}");
                        else
                            _log.Info(sourceLabel, $"{parsed.Method} {parsed.Host}:{parsed.Port}  {via}");

                        await PipeAsync(clientStream, remoteStream, ct);
                    }
                }
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _stats.Errors);
                _stats.LastError = ex.Message;
                _log.Error(sourceLabel, $"{parsed.Method} {parsed.Host}:{parsed.Port}  {via}  {ex.Message}");
                try
                {
                    var body = Encoding.ASCII.GetBytes("Bad Gateway");
                    var resp = Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
                    await clientStream.WriteAsync(resp, ct);
                    await clientStream.WriteAsync(body, ct);
                }
                catch
                {
                    // ignored
                }
            }
        }
        catch (OperationCanceledException)
        {
            // shutdown
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _stats.Errors);
            _stats.LastError = ex.Message;
            _log.Error(sourceLabel, ex.Message);
        }
        finally
        {
            Interlocked.Decrement(ref _stats.Active);
            try { client.Close(); } catch { /* ignore */ }
            client.Dispose();
        }
    }

    private async Task PipeAsync(Stream a, Stream b, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = linked.Token;

        var t1 = CopyAsync(a, b, up: true, token);
        var t2 = CopyAsync(b, a, up: false, token);
        await Task.WhenAny(t1, t2);
        linked.Cancel();
        try { await Task.WhenAll(t1, t2); } catch { /* ignore */ }
    }

    private async Task CopyAsync(Stream src, Stream dst, bool up, CancellationToken ct)
    {
        var buf = new byte[81920];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var n = await src.ReadAsync(buf.AsMemory(0, buf.Length), ct);
                if (n == 0)
                    break;
                await dst.WriteAsync(buf.AsMemory(0, n), ct);
                if (up)
                    Interlocked.Add(ref _stats.BytesUp, n);
                else
                    Interlocked.Add(ref _stats.BytesDown, n);
            }
        }
        catch
        {
            // peer closed
        }
    }

    private static bool IsLocal(IPEndPoint? ep)
    {
        if (ep is null)
            return true;
        return IPAddress.IsLoopback(ep.Address);
    }

    private static async Task<(byte[] headers, byte[] leftover)> ReadHeadersAsync(NetworkStream stream, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        var buf = new byte[4096];
        var needle = "\r\n\r\n"u8.ToArray();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));

        while (ms.Length < 65536)
        {
            var n = await stream.ReadAsync(buf, timeout.Token);
            if (n == 0)
                return (Array.Empty<byte>(), Array.Empty<byte>());
            ms.Write(buf, 0, n);
            var data = ms.ToArray();
            var idx = UpstreamClient.IndexOf(data, needle);
            if (idx >= 0)
            {
                var headers = new byte[idx + 4];
                Buffer.BlockCopy(data, 0, headers, 0, headers.Length);
                var leftover = new byte[data.Length - headers.Length];
                if (leftover.Length > 0)
                    Buffer.BlockCopy(data, headers.Length, leftover, 0, leftover.Length);
                return (headers, leftover);
            }
        }

        throw new IOException("Слишком большие HTTP-заголовки.");
    }
}

internal sealed class HttpProxyRequest
{
    public string Method { get; private init; } = "GET";
    public string Host { get; private init; } = "";
    public int Port { get; private init; } = 80;
    public bool IsConnect { get; private init; }
    public string Path { get; private init; } = "/";
    public string Version { get; private init; } = "HTTP/1.1";
    public List<KeyValuePair<string, string>> Headers { get; } = new();

    public static HttpProxyRequest Parse(byte[] rawHeaders)
    {
        var text = Encoding.ASCII.GetString(rawHeaders);
        var lines = text.Split(new[] { "\r\n" }, StringSplitOptions.None);
        if (lines.Length == 0 || string.IsNullOrWhiteSpace(lines[0]))
            throw new IOException("Пустой HTTP-запрос.");

        var parts = lines[0].Split(' ');
        if (parts.Length < 3)
            throw new IOException("Некорректная request line.");

        var method = parts[0].ToUpperInvariant();
        var target = parts[1];
        var version = parts[2];
        var headers = new List<KeyValuePair<string, string>>();
        string? hostHeader = null;

        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrEmpty(line))
                continue;
            var colon = line.IndexOf(':');
            if (colon <= 0)
                continue;
            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (name.Equals("Host", StringComparison.OrdinalIgnoreCase))
                hostHeader = value;
            if (IsHopByHop(name))
                continue;
            headers.Add(new KeyValuePair<string, string>(name, value));
        }

        var isConnect = method == "CONNECT";
        string host;
        int port;
        var path = "/";

        if (isConnect)
        {
            SplitHostPort(target, 443, out host, out port);
        }
        else if (Uri.TryCreate(target, UriKind.Absolute, out var uri))
        {
            host = uri.Host;
            port = uri.IsDefaultPort ? (uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80) : uri.Port;
            path = uri.PathAndQuery;
            if (string.IsNullOrEmpty(path))
                path = "/";
        }
        else
        {
            path = target.StartsWith('/') ? target : "/" + target;
            if (string.IsNullOrWhiteSpace(hostHeader))
                throw new IOException("Нет Host в запросе.");
            SplitHostPort(hostHeader, 80, out host, out port);
        }

        var parsed = new HttpProxyRequest
        {
            Method = method,
            Host = host,
            Port = port,
            IsConnect = isConnect,
            Path = path,
            Version = version
        };
        parsed.Headers.AddRange(headers);
        if (!parsed.Headers.Any(h => h.Key.Equals("Host", StringComparison.OrdinalIgnoreCase)))
            parsed.Headers.Insert(0, new KeyValuePair<string, string>("Host", port is 80 or 443 ? host : $"{host}:{port}"));
        return parsed;
    }

    public byte[] BuildOriginRequest()
    {
        var sb = new StringBuilder();
        sb.Append($"{Method} {Path} {Version}\r\n");
        foreach (var h in Headers)
            sb.Append($"{h.Key}: {h.Value}\r\n");
        sb.Append("Connection: close\r\n\r\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    public byte[] BuildProxyRequest(AppConfig config)
    {
        var hostPart = Host.Contains(':') ? $"[{Host}]" : Host;
        var authority = Port == 80 ? hostPart : $"{hostPart}:{Port}";
        var sb = new StringBuilder();
        sb.Append($"{Method} http://{authority}{Path} {Version}\r\n");
        foreach (var h in Headers)
            sb.Append($"{h.Key}: {h.Value}\r\n");
        UpstreamClient.AppendProxyAuthorization(sb, config);
        sb.Append("Proxy-Connection: close\r\n");
        sb.Append("Connection: close\r\n\r\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    private static bool IsHopByHop(string name) =>
        name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Connection", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase);

    private static void SplitHostPort(string target, int defaultPort, out string host, out int port)
    {
        target = target.Trim();
        if (target.StartsWith('['))
        {
            var rb = target.IndexOf(']');
            host = target[1..rb];
            port = defaultPort;
            if (rb + 2 < target.Length && target[rb + 1] == ':')
                port = int.Parse(target[(rb + 2)..]);
            return;
        }

        var idx = target.LastIndexOf(':');
        if (idx > 0 && int.TryParse(target[(idx + 1)..], out var p))
        {
            host = target[..idx];
            port = p;
            return;
        }

        host = target;
        port = defaultPort;
    }
}
