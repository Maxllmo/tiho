using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using ProxyHub.Models;

namespace ProxyHub.Services;

public static class ProxyTester
{
    private const string TestHost = "api.ipify.org";

    public static async Task<int> TcpPingAsync(string host, int port, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(host) || port is <= 0 or > 65535)
            throw new InvalidOperationException("Не задан хост или порт.");

        var sw = Stopwatch.StartNew();
        using var tcp = new TcpClient { NoDelay = true };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        await tcp.ConnectAsync(host.Trim(), port, timeout.Token);
        sw.Stop();
        return (int)Math.Max(1, sw.ElapsedMilliseconds);
    }

    public static async Task<string> TestAsync(AppConfig config, CancellationToken ct)
    {
        if (!config.IsConfigured)
            throw new InvalidOperationException("Сначала добавьте и подключите сервер.");

        // HTTPS CONNECT :443 — так ходят PS5 и браузер. CONNECT :80 многие HTTP-прокси режут 403.
        await using var raw = await UpstreamClient.OpenAsync(config, TestHost, 443, bypass: false, ct);
        using var ssl = new SslStream(raw, leaveInnerStreamOpen: true);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = TestHost
        }, ct);

        var req = $"GET / HTTP/1.1\r\nHost: {TestHost}\r\nUser-Agent: ProxyHub\r\nConnection: close\r\n\r\n";
        await ssl.WriteAsync(Encoding.ASCII.GetBytes(req), ct);

        using var reader = new StreamReader(ssl, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
        var response = await reader.ReadToEndAsync(ct);
        var split = response.Split(new[] { "\r\n\r\n" }, 2, StringSplitOptions.None);
        var status = split[0].Split('\n')[0].Trim();
        if (status.Length > 0 && !status.Contains(" 200"))
            throw new IOException($"Проверка через HTTPS не удалась: {status}");

        var body = split.Length > 1 ? split[1].Trim() : "";
        if (string.IsNullOrWhiteSpace(body) || body.Length > 64)
            throw new IOException("Прокси ответил, но исходящий IP не распознан.");

        return body;
    }
}
