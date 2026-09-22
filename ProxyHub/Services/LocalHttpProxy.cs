using System.Collections.Concurrent;
using System.Diagnostics;
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
    private readonly ClientTracker _clients;
    private readonly Func<AppConfig> _config;
    private CancellationTokenSource? _cts;
    private TcpListener? _listener;
    private Task? _acceptLoop;
    private UdpClient? _udp;
    private Task? _udpLoop;
    private readonly ConcurrentDictionary<int, byte> _directOnlyPorts = new();
    private readonly ConcurrentDictionary<string, long> _errorLogAt = new();
    private readonly SemaphoreSlim _directConnects = new(8, 8);

    public bool IsRunning { get; private set; }
    public int BoundPort { get; private set; }

    public LocalHttpProxy(LogService log, HubStats stats, ClientTracker clients, Func<AppConfig> config)
    {
        _log = log;
        _stats = stats;
        _clients = clients;
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
        StartSharedUdp(ct);
        _log.Sys($"Локальный HTTP/SOCKS-прокси слушает 0.0.0.0:{BoundPort}");
        TryAllowFirewall();
        await Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        if (!IsRunning)
            return;

        IsRunning = false;
        try { _cts?.Cancel(); } catch { /* ignore */ }
        try { _listener?.Stop(); } catch { /* ignore */ }
        try { _udp?.Close(); } catch { /* ignore */ }
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop; } catch { /* ignore */ }
        }
        if (_udpLoop is not null)
        {
            try { await _udpLoop; } catch { /* ignore */ }
        }
        try { _udp?.Dispose(); } catch { /* ignore */ }
        _udp = null;
        _udpLoop = null;
        _cts?.Dispose();
        _cts = null;
        _listener = null;
        _acceptLoop = null;
        _log.Sys("Локальный HTTP-прокси остановлен.");
    }

    private void StartSharedUdp(CancellationToken ct)
    {
        try
        {
            _udp = new UdpClient(new IPEndPoint(IPAddress.Any, BoundPort));
            var session = _clients.Begin("UDP", "UDP");
            _udpLoop = Task.Run(() => RelaySocksUdpAsync(_udp, null, session, ct), ct);
        }
        catch (Exception ex)
        {
            _log.Sys($"UDP {BoundPort}: {ex.Message}");
        }
    }

    private static void TryAllowFirewall()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exe))
                return;
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = $"advfirewall firewall add rule name=\"ProxyHub\" dir=in action=allow program=\"{exe}\" profile=any",
                CreateNoWindow = true,
                UseShellExecute = false,
            };
            Process.Start(psi)?.Dispose();
        }
        catch
        {
            // без прав администратора правило может не создаться
        }
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
        Interlocked.Increment(ref _stats.Active);
        Interlocked.Increment(ref _stats.Requests);

        var remote = client.Client.RemoteEndPoint as IPEndPoint;
        var isLocal = ClientTracker.KeyFrom(remote) == ClientTracker.PcKey;
        string? sessionKey = null;

        try
        {
            using var clientStream = client.GetStream();
            var first = new byte[1];
            var n = await clientStream.ReadAsync(first.AsMemory(0, 1), ct);
            if (n == 0)
                return;

            if (first[0] == 5)
                sessionKey = await HandleSocksAsync(clientStream, remote, isLocal, ct);
            else
                sessionKey = await HandleHttpAsync(clientStream, first, remote, isLocal, ct);
        }
        catch (OperationCanceledException)
        {
            // shutdown
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _stats.Errors);
            _stats.LastError = ex.Message;
            _log.Error(isLocal ? ClientTracker.PcKey : remote?.Address.ToString() ?? "?", ex.Message);
        }
        finally
        {
            Interlocked.Decrement(ref _stats.Active);
            if (sessionKey is not null)
                _clients.End(sessionKey);
            try { client.Close(); } catch { /* ignore */ }
            client.Dispose();
        }
    }

    private async Task<string?> HandleHttpAsync(
        NetworkStream clientStream,
        byte[] prefix,
        IPEndPoint? remote,
        bool isLocal,
        CancellationToken ct)
    {
        var (headerBytes, leftover) = await ReadHeadersAsync(clientStream, prefix, ct);
        if (headerBytes.Length == 0)
            return null;

        var requestLine = RequestLine(headerBytes);
        if (IsOriginForm(requestLine.method, requestLine.target))
        {
            await ServeLocalHttpAsync(clientStream, requestLine.method, requestLine.target, ct);
            return null;
        }

        var parsed = HttpProxyRequest.Parse(headerBytes);
        var identity = await AuthenticateHttpAsync(clientStream, parsed, remote, isLocal, ct);
        if (identity is null)
            return null;

        var session = _clients.Begin(identity.Key, identity.Name);
        try
        {
            await ProxyHttpAsync(clientStream, leftover, parsed, identity.Key, session, ct);
            return identity.Key;
        }
        catch
        {
            _clients.End(identity.Key);
            throw;
        }
    }

    private async Task ProxyHttpAsync(
        NetworkStream clientStream,
        byte[] leftover,
        HttpProxyRequest parsed,
        string sourceLabel,
        ClientSession session,
        CancellationToken ct)
    {
        var cfg = _config();
        var bypass = BypassRules.ShouldBypass(parsed.Host, out var bypassReason);
        var via = bypass ? $"DIRECT ({bypassReason})" : cfg.UpstreamType;
        var viaOut = new[] { via };
        var httpForward = !bypass
            && !parsed.IsConnect
            && cfg.UpstreamType.Equals("HTTP", StringComparison.OrdinalIgnoreCase);

        try
        {
            Stream remoteStream;
            if (httpForward)
            {
                remoteStream = await UpstreamClient.ConnectHttpProxyAsync(cfg, ct);
            }
            else
            {
                remoteStream = await OpenTunnelAsync(cfg, parsed.Host, parsed.Port, bypass, bypassReason, viaOut, ct);
                via = viaOut[0];
            }

            await using (remoteStream)
            {
                if (parsed.IsConnect)
                {
                    var ok = "HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray();
                    await clientStream.WriteAsync(ok, ct);
                    await clientStream.FlushAsync(ct);
                    if (leftover.Length > 0)
                        await remoteStream.WriteAsync(leftover, ct);
                    session.SetHost($"{parsed.Host}:{parsed.Port}");
                    if (via.StartsWith("DIRECT", StringComparison.Ordinal))
                        _log.Bypass(sourceLabel, $"CONNECT {parsed.Host}:{parsed.Port}  {via}");
                    else
                        _log.Info(sourceLabel, $"CONNECT {parsed.Host}:{parsed.Port}  {via}");

                    await PipeAsync(clientStream, remoteStream, session, ct);
                }
                else
                {
                    var forwarded = httpForward ? parsed.BuildProxyRequest(cfg) : parsed.BuildOriginRequest();
                    await remoteStream.WriteAsync(forwarded, ct);
                    if (leftover.Length > 0)
                        await remoteStream.WriteAsync(leftover, ct);

                    session.SetHost($"{parsed.Host}:{parsed.Port}");
                    if (bypass)
                        _log.Bypass(sourceLabel, $"{parsed.Method} {parsed.Host}:{parsed.Port}  {via}");
                    else
                        _log.Info(sourceLabel, $"{parsed.Method} {parsed.Host}:{parsed.Port}  {via}");

                    await PipeAsync(clientStream, remoteStream, session, ct);
                }
            }
        }
        catch (Exception) when (ct.IsCancellationRequested)
        {
            // остановка хаба
        }
        catch (Exception ex)
        {
            ReportError(sourceLabel, $"{parsed.Method} {parsed.Host}:{parsed.Port}  {viaOut[0]}  {ex.Message}");
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

    private async Task<ClientIdentity?> AuthenticateHttpAsync(
        NetworkStream clientStream,
        HttpProxyRequest parsed,
        IPEndPoint? remote,
        bool isLocal,
        CancellationToken ct)
    {
        if (isLocal)
            return new ClientIdentity(ClientTracker.PcKey, ClientTracker.DisplayName(ClientTracker.PcKey));

        var ip = remote?.Address.ToString() ?? "?";
        _log.Error(ip, "Подключение не с этого ПК");
        var body = Encoding.ASCII.GetBytes("Proxy authentication required");
        var resp = Encoding.ASCII.GetBytes(
            "HTTP/1.1 407 Proxy Authentication Required\r\n" +
            "Proxy-Authenticate: Basic realm=\"ProxyHub\"\r\n" +
            $"Content-Length: {body.Length}\r\n" +
            "Connection: close\r\n\r\n");
        await clientStream.WriteAsync(resp, ct);
        await clientStream.WriteAsync(body, ct);
        return null;
    }

    private async Task ServeLocalHttpAsync(
        NetworkStream stream,
        string method,
        string target,
        CancellationToken ct)
    {
        var path = target;
        var q = path.IndexOf('?', StringComparison.Ordinal);
        if (q >= 0)
            path = path[..q];

        if (method is "GET" or "HEAD" && path is "/" or "/health")
        {
            await WritePlain(stream, 200, "Proxy Hub", ct);
            return;
        }

        await WritePlain(stream, 404, "not found", ct);
    }

    private async Task<string?> HandleSocksAsync(
        NetworkStream stream,
        IPEndPoint? remote,
        bool isLocal,
        CancellationToken ct)
    {
        var nMethodsBuf = await UpstreamClient.ReadExactAsync(stream, 1, ct);
        var nMethods = nMethodsBuf[0];
        var methods = nMethods == 0
            ? Array.Empty<byte>()
            : await UpstreamClient.ReadExactAsync(stream, nMethods, ct);

        var hasUserPass = methods.Contains((byte)2);
        var hasNone = methods.Contains((byte)0);

        if (hasUserPass)
        {
            await stream.WriteAsync(new byte[] { 5, 2 }, ct);
            if (!await ReadSocksUserPassAsync(stream, ct) || !isLocal)
            {
                await stream.WriteAsync(new byte[] { 1, 1 }, ct);
                if (!isLocal)
                {
                    var ip = remote?.Address.ToString() ?? "?";
                    _log.Error(ip, "SOCKS5 не с этого ПК");
                }
                return null;
            }

            await stream.WriteAsync(new byte[] { 1, 0 }, ct);
            var authed = new ClientIdentity(ClientTracker.PcKey, ClientTracker.DisplayName(ClientTracker.PcKey));
            return await SocksConnectAsync(stream, authed, remote, ct);
        }

        if (isLocal && hasNone)
        {
            await stream.WriteAsync(new byte[] { 5, 0 }, ct);
            var local = new ClientIdentity(ClientTracker.PcKey, ClientTracker.DisplayName(ClientTracker.PcKey));
            return await SocksConnectAsync(stream, local, remote, ct);
        }

        await stream.WriteAsync(new byte[] { 5, 0xFF }, ct);
        if (!isLocal)
        {
            var ip = remote?.Address.ToString() ?? "?";
            _log.Error(ip, "SOCKS5 без ключа");
        }
        return null;
    }

    private async Task<string?> SocksConnectAsync(
        NetworkStream stream,
        ClientIdentity identity,
        IPEndPoint? clientEp,
        CancellationToken ct)
    {
        var head = await UpstreamClient.ReadExactAsync(stream, 4, ct);
        if (head[0] != 5)
            return null;

        var (host, port) = await ReadSocksAddressAsync(stream, head[3], ct);
        if (head[1] == 3)
            return await SocksUdpAssociateAsync(stream, identity, clientEp, ct);
        if (head[1] != 1)
        {
            await stream.WriteAsync(new byte[] { 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 }, ct);
            return null;
        }

        var session = _clients.Begin(identity.Key, identity.Name);
        var cfg = _config();
        var bypass = BypassRules.ShouldBypass(host, out var bypassReason);
        var via = bypass ? $"DIRECT ({bypassReason})" : cfg.UpstreamType;
        var viaOut = new[] { via };
        try
        {
            var remoteStream = await OpenTunnelAsync(cfg, host, port, bypass, bypassReason, viaOut, ct);
            via = viaOut[0];
            await using (remoteStream)
            {
                await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, ct);
                session.SetHost($"{host}:{port}");
                if (via.StartsWith("DIRECT", StringComparison.Ordinal))
                    _log.Bypass(identity.Key, $"SOCKS {host}:{port}  {via}");
                else
                    _log.Info(identity.Key, $"SOCKS {host}:{port}  {via}");
                await PipeAsync(stream, remoteStream, session, ct);
            }
            return identity.Key;
        }
        catch (Exception) when (ct.IsCancellationRequested)
        {
            _clients.End(identity.Key);
            return null;
        }
        catch (Exception ex)
        {
            ReportError(identity.Key, $"SOCKS {host}:{port}  {viaOut[0]}  {ex.Message}");
            try { await stream.WriteAsync(new byte[] { 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }, ct); } catch { /* ignore */ }
            _clients.End(identity.Key);
            return null;
        }
    }

    private static async Task<(string host, int port)> ReadSocksAddressAsync(
        NetworkStream stream,
        byte atyp,
        CancellationToken ct)
    {
        if (atyp == 1)
        {
            var addr = await UpstreamClient.ReadExactAsync(stream, 4, ct);
            return (new IPAddress(addr).ToString(), ReadPort(await UpstreamClient.ReadExactAsync(stream, 2, ct)));
        }
        if (atyp == 4)
        {
            var addr = await UpstreamClient.ReadExactAsync(stream, 16, ct);
            return (new IPAddress(addr).ToString(), ReadPort(await UpstreamClient.ReadExactAsync(stream, 2, ct)));
        }
        if (atyp == 3)
        {
            var len = await UpstreamClient.ReadExactAsync(stream, 1, ct);
            var name = await UpstreamClient.ReadExactAsync(stream, len[0], ct);
            return (Encoding.UTF8.GetString(name), ReadPort(await UpstreamClient.ReadExactAsync(stream, 2, ct)));
        }
        throw new IOException($"SOCKS5: неизвестный ATYP {atyp}");
    }

    private async Task<string?> SocksUdpAssociateAsync(
        NetworkStream stream,
        ClientIdentity identity,
        IPEndPoint? clientEp,
        CancellationToken ct)
    {
        var bindIp = (stream.Socket?.LocalEndPoint as IPEndPoint)?.Address ?? IPAddress.Loopback;
        if (bindIp.IsIPv4MappedToIPv6)
            bindIp = bindIp.MapToIPv4();
        if (IPAddress.Any.Equals(bindIp) || IPAddress.IPv6Any.Equals(bindIp) || bindIp.AddressFamily != AddressFamily.InterNetwork)
            bindIp = IPAddress.Loopback;

        var bindPort = BoundPort > 0 ? BoundPort : 3128;
        var ipBytes = bindIp.GetAddressBytes();
        var reply = new byte[10];
        reply[0] = 5;
        reply[3] = 1;
        Buffer.BlockCopy(ipBytes.Length == 4 ? ipBytes : new byte[4], 0, reply, 4, 4);
        reply[8] = (byte)(bindPort >> 8);
        reply[9] = (byte)bindPort;
        await stream.WriteAsync(reply, ct);

        var session = _clients.Begin(identity.Key, identity.Name);
        session.SetHost($"UDP {bindIp}:{bindPort}");
        _log.Info(identity.Key, $"SOCKS UDP {bindIp}:{bindPort}");
        try
        {
            var buf = new byte[1];
            try
            {
                await stream.ReadAsync(buf.AsMemory(0, 1), ct);
            }
            catch
            {
                // TCP closed — UDP associate ends
            }
            return identity.Key;
        }
        finally
        {
            _clients.End(identity.Key);
        }
    }

    private async Task RelaySocksUdpAsync(
        UdpClient udp,
        IPEndPoint? tcpClient,
        ClientSession session,
        CancellationToken ct)
    {
        IPEndPoint? socksClient = null;
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult packet;
            try
            {
                packet = await udp.ReceiveAsync(ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch
            {
                return;
            }

            var from = packet.RemoteEndPoint;
            var data = packet.Buffer;
            var fromClient = tcpClient is null || from.Address.Equals(tcpClient.Address);

            if (fromClient && data.Length >= 10 && data[0] == 0 && data[1] == 0 && data[2] == 0)
            {
                if (!TryParseSocksUdp(data, out var dest, out var payload) || dest is null || payload.Length == 0)
                    continue;
                socksClient = from;
                try
                {
                    await udp.SendAsync(payload, dest, ct);
                    _clients.AddUp(session, payload.Length);
                    Interlocked.Add(ref _stats.BytesUp, payload.Length);
                }
                catch
                {
                    // drop
                }
                continue;
            }

            if (socksClient is null)
                continue;

            var wrapped = WrapSocksUdp(from, data);
            try
            {
                await udp.SendAsync(wrapped, socksClient, ct);
                _clients.AddDown(session, data.Length);
                Interlocked.Add(ref _stats.BytesDown, data.Length);
            }
            catch
            {
                // drop
            }
        }
    }

    private static bool TryParseSocksUdp(byte[] data, out IPEndPoint? dest, out byte[] payload)
    {
        dest = null;
        payload = Array.Empty<byte>();
        try
        {
            var atyp = data[3];
            var offset = 4;
            IPAddress ip;
            if (atyp == 1)
            {
                if (data.Length < 10) return false;
                ip = new IPAddress(data.AsSpan(4, 4));
                offset = 8;
            }
            else if (atyp == 4)
            {
                if (data.Length < 22) return false;
                ip = new IPAddress(data.AsSpan(4, 16));
                offset = 20;
            }
            else if (atyp == 3)
            {
                var len = data[4];
                if (data.Length < 7 + len) return false;
                var name = Encoding.UTF8.GetString(data, 5, len);
                offset = 5 + len;
                var portName = (data[offset] << 8) | data[offset + 1];
                offset += 2;
                dest = new IPEndPoint(Dns.GetHostAddresses(name)[0], portName);
                payload = data[offset..];
                return dest.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6;
            }
            else
                return false;

            var port = (data[offset] << 8) | data[offset + 1];
            offset += 2;
            dest = new IPEndPoint(ip, port);
            payload = data[offset..];
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] WrapSocksUdp(IPEndPoint src, byte[] payload)
    {
        var addr = src.Address;
        if (addr.IsIPv4MappedToIPv6)
            addr = addr.MapToIPv4();
        var ip = addr.GetAddressBytes();
        var v4 = addr.AddressFamily == AddressFamily.InterNetwork;
        var packet = new byte[(v4 ? 10 : 22) + payload.Length];
        packet[3] = (byte)(v4 ? 1 : 4);
        var ipOff = 4;
        Buffer.BlockCopy(ip, 0, packet, ipOff, ip.Length);
        var portOff = ipOff + ip.Length;
        packet[portOff] = (byte)(src.Port >> 8);
        packet[portOff + 1] = (byte)src.Port;
        Buffer.BlockCopy(payload, 0, packet, portOff + 2, payload.Length);
        return packet;
    }

    private static async Task<bool> ReadSocksUserPassAsync(NetworkStream stream, CancellationToken ct)
    {
        var ver = await UpstreamClient.ReadExactAsync(stream, 2, ct);
        if (ver[0] != 1)
            return false;
        if (ver[1] > 0)
            await UpstreamClient.ReadExactAsync(stream, ver[1], ct);
        var plen = await UpstreamClient.ReadExactAsync(stream, 1, ct);
        if (plen[0] > 0)
            await UpstreamClient.ReadExactAsync(stream, plen[0], ct);
        return true;
    }

    private static int ReadPort(byte[] bytes)
        => (bytes[0] << 8) | bytes[1];

    private async Task PipeAsync(Stream a, Stream b, ClientSession session, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = linked.Token;

        var t1 = CopyAsync(a, b, up: true, session, token);
        var t2 = CopyAsync(b, a, up: false, session, token);
        await Task.WhenAny(t1, t2);
        linked.Cancel();
        try { await Task.WhenAll(t1, t2); } catch { /* ignore */ }
    }

    private async Task CopyAsync(Stream src, Stream dst, bool up, ClientSession session, CancellationToken ct)
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
                {
                    Interlocked.Add(ref _stats.BytesUp, n);
                    _clients.AddUp(session, n);
                }
                else
                {
                    Interlocked.Add(ref _stats.BytesDown, n);
                    _clients.AddDown(session, n);
                }
            }
        }
        catch
        {
            // peer closed
        }
    }

    private static async Task<(byte[] headers, byte[] leftover)> ReadHeadersAsync(
        NetworkStream stream,
        byte[] prefix,
        CancellationToken ct)
    {
        using var ms = new MemoryStream();
        if (prefix.Length > 0)
            ms.Write(prefix, 0, prefix.Length);
        var buf = new byte[4096];
        var needle = "\r\n\r\n"u8.ToArray();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));

        if (ms.Length >= 4)
        {
            var early = ms.ToArray();
            var earlyIdx = UpstreamClient.IndexOf(early, needle);
            if (earlyIdx >= 0)
            {
                var headers = new byte[earlyIdx + 4];
                Buffer.BlockCopy(early, 0, headers, 0, headers.Length);
                var leftover = new byte[early.Length - headers.Length];
                if (leftover.Length > 0)
                    Buffer.BlockCopy(early, headers.Length, leftover, 0, leftover.Length);
                return (headers, leftover);
            }
        }

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

    private static (string method, string target, string host) RequestLine(byte[] rawHeaders)
    {
        var text = Encoding.ASCII.GetString(rawHeaders);
        var lines = text.Split(new[] { "\r\n" }, StringSplitOptions.None);
        var parts = (lines.Length == 0 ? "" : lines[0]).Split(' ');
        var method = parts.Length > 0 ? parts[0].ToUpperInvariant() : "";
        var target = parts.Length > 1 ? parts[1] : "/";
        var host = "";
        for (var i = 1; i < lines.Length; i++)
        {
            if (lines[i].StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
            {
                host = lines[i][5..].Trim();
                break;
            }
        }
        return (method, target, host);
    }

    private static bool IsOriginForm(string method, string target)
        => method != "CONNECT" && target.StartsWith('/');

    private static async Task WritePlain(Stream stream, int status, string text, CancellationToken ct)
    {
        var body = Encoding.UTF8.GetBytes(text);
        await WriteBytes(stream, status, "text/plain; charset=utf-8", body, ct);
    }

    private static async Task WriteBytes(Stream stream, int status, string contentType, byte[] body, CancellationToken ct)
    {
        var reason = status switch
        {
            200 => "OK",
            403 => "Forbidden",
            404 => "Not Found",
            407 => "Proxy Authentication Required",
            _ => "Error"
        };
        var header = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {status} {reason}\r\n" +
            $"Content-Type: {contentType}\r\n" +
            "Cache-Control: no-store\r\n" +
            "Connection: close\r\n" +
            $"Content-Length: {body.Length}\r\n\r\n");
        await stream.WriteAsync(header, ct);
        if (body.Length > 0)
            await stream.WriteAsync(body, ct);
        await stream.FlushAsync(ct);
    }

    private async Task<Stream> OpenTunnelAsync(
        AppConfig cfg,
        string host,
        int port,
        bool bypass,
        string bypassReason,
        string[] via,
        CancellationToken ct)
    {
        if (bypass)
        {
            via[0] = $"DIRECT ({bypassReason})";
            return await UpstreamClient.ConnectDirectAsync(host, port, ct);
        }

        if (port != 443 && _directOnlyPorts.ContainsKey(port))
        {
            via[0] = DirectPortVia(port);
            return await ConnectDirectLimitedAsync(host, port, ct);
        }

        try
        {
            var stream = await UpstreamClient.OpenAsync(cfg, host, port, false, ct);
            via[0] = cfg.UpstreamType;
            return stream;
        }
        catch (HttpConnectDeniedException ex) when (port != 443 && ex.StatusCode is 403 or 405 or 501)
        {
            if (_directOnlyPorts.TryAdd(port, 1))
                _log.Sys($"Squid не туннелит порт {port}. Дальше такие CONNECT идут напрямую и не долбят прокси.");
            via[0] = DirectPortVia(port);
            return await ConnectDirectLimitedAsync(host, port, ct);
        }
    }

    private async Task<Stream> ConnectDirectLimitedAsync(string host, int port, CancellationToken ct)
    {
        if (!await _directConnects.WaitAsync(0, ct))
            throw new IOException($"Порт {port}: слишком много прямых подключений, запрос пропущен.");

        try
        {
            return await UpstreamClient.ConnectDirectAsync(host, port, ct, TimeSpan.FromSeconds(4));
        }
        finally
        {
            _directConnects.Release();
        }
    }

    private static string DirectPortVia(int port) => $"DIRECT (Squid не туннелит порт {port})";

    private void ReportError(string source, string message)
    {
        var now = Environment.TickCount64;
        if (_errorLogAt.TryGetValue(message, out var last) && now - last < 60_000)
            return;

        _errorLogAt[message] = now;
        if (_errorLogAt.Count > 4000)
            _errorLogAt.Clear();

        Interlocked.Increment(ref _stats.Errors);
        _stats.LastError = message;
        _log.Error(source, message);
    }

    private sealed record ClientIdentity(string Key, string Name);
}

internal sealed class HttpProxyRequest
{
    public string Method { get; private init; } = "GET";
    public string Host { get; private init; } = "";
    public int Port { get; private init; } = 80;
    public bool IsConnect { get; private init; }
    public string Path { get; private init; } = "/";
    public string Version { get; private init; } = "HTTP/1.1";
    public string? ProxyAuthorization { get; private init; }
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
        string? proxyAuth = null;

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
            if (name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase))
                proxyAuth = value;
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
            Version = version,
            ProxyAuthorization = proxyAuth
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
