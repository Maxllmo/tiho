using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.Json;
using ProxyHub.Models;

namespace ProxyHub.Services;

public sealed record TunnelCounters(long Upload, long Download, int Connections);

public sealed class TunnelService : IAsyncDisposable
{
    public const string CoreVersion = "1.14.4";
    private readonly List<Process> _processes = new();
    private readonly WindowsJob _job = new();
    private HttpClient? _api;
    private string? _runningId;
    public bool IsRunning => _api is not null && _processes.Count > 0 && _processes.All(p => !p.HasExited);
    public string? RunningProfileId => IsRunning ? _runningId : null;
    public static string CoreDirectory => Path.Combine(AppContext.BaseDirectory, "Core", System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture switch
    {
        System.Runtime.InteropServices.Architecture.Arm64 => "arm64", System.Runtime.InteropServices.Architecture.X86 => "x86", _ => "x64"
    });

    public async Task StartAsync(AppConfig config, LogService log, CancellationToken ct)
    {
        await StopAsync();
        var profile = config.ActiveProfile ?? throw new InvalidOperationException("Добавьте сервер в настройках.");
        if (!profile.IsConfigured) throw new InvalidOperationException("Укажите корректный сервер и порт.");
        var singBox = Path.Combine(CoreDirectory, "sing-box.exe");
        if (!File.Exists(singBox)) throw new FileNotFoundException("Не найдено VPN-ядро. Переустановите Tiho из полного установщика.");
        var endpoints = await Dns.GetHostAddressesAsync(profile.Host, ct);
        if (endpoints.Length == 0) throw new InvalidOperationException("Не удалось определить адрес сервера.");
        var socksPort = FreePort();
        var apiPort = FreePort();
        while (apiPort == socksPort) apiPort = FreePort();
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var rulesDir = RoutingRules.DirectoryPath;
        try
        {
            if (profile.IsAmnezia)
            {
                var gateway = Path.Combine(CoreDirectory, "tiho-awg.exe");
                if (!File.Exists(gateway)) throw new FileNotFoundException("Не найдено ядро AmneziaWG. Переустановите Tiho.");
                // Both cores receive secrets over stdin; no plaintext config or keys in command-line arguments.
                Launch(gateway, "", JsonSerializer.Serialize(new { config = profile.WireGuardConfig, listen = $"127.0.0.1:{socksPort}" }), log);
                await WaitForPortAsync(socksPort, ct);
            }
            var coreConfig = TunnelConfig.Build(config, socksPort, apiPort, token, rulesDir, endpoints.Select(ip => ip.ToString()), PhysicalDnsServer());
            Launch(singBox, "--disable-color run -c stdin", coreConfig.ToJsonString(), log);
            _api = new HttpClient(new HttpClientHandler { UseProxy = false })
            { BaseAddress = new Uri($"http://127.0.0.1:{apiPort}/"), Timeout = TimeSpan.FromSeconds(4) };
            _api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            await WaitForPortAsync(apiPort, ct);
            await GetCountersAsync(ct);
            _runningId = profile.Id;
            log.Sys($"Подключён {profile.Name}. Режим: весь ПК. Россия: {(config.BypassRussia ? "напрямую" : "через сервер")}. Исключений программ: {config.ExcludedApps.Count}.");
            if (profile.Protocol.Equals("HTTP", StringComparison.OrdinalIgnoreCase))
                log.Sys("HTTP-прокси не поддерживает UDP. Для игр используйте профиль AmneziaWG.");
        }
        catch { await StopAsync(); throw; }
    }

    private void Launch(string exe, string arguments, string input, LogService log)
    {
        var info = new ProcessStartInfo(exe, arguments)
        {
            WorkingDirectory = CoreDirectory, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false), StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
        };
        var process = new Process { StartInfo = info };
        process.OutputDataReceived += (_, e) => CoreLog(log, e.Data);
        process.ErrorDataReceived += (_, e) => CoreLog(log, e.Data);
        if (!process.Start()) throw new InvalidOperationException("Не удалось запустить VPN-ядро.");
        _processes.Add(process);
        _job.Add(process);
        process.BeginOutputReadLine(); process.BeginErrorReadLine();
        process.StandardInput.Write(input); process.StandardInput.Close();
    }

    private static void CoreLog(LogService log, string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        if (line.Contains("ERROR", StringComparison.OrdinalIgnoreCase) || line.Contains("FATAL", StringComparison.OrdinalIgnoreCase)) log.Error("VPN", line);
        else if (line.Contains("outbound/direct", StringComparison.OrdinalIgnoreCase)) log.Bypass("DIRECT", line);
        else log.Info("VPN", line);
    }

    private async Task WaitForPortAsync(int port, CancellationToken ct)
    {
        var until = Stopwatch.StartNew();
        while (until.Elapsed < TimeSpan.FromSeconds(20))
        {
            ct.ThrowIfCancellationRequested();
            if (_processes.Any(p => p.HasExited)) throw new InvalidOperationException("VPN-ядро завершилось при запуске. Подробности на вкладке «Логи».");
            try { using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, port, ct); return; }
            catch (SocketException) { await Task.Delay(150, ct); }
        }
        throw new TimeoutException("VPN-ядро не запустилось за 20 секунд. Подробности в логах.");
    }

    public async Task<TunnelCounters> GetCountersAsync(CancellationToken ct)
    {
        var api = _api ?? throw new InvalidOperationException("VPN выключен.");
        using var response = await api.GetAsync("connections", ct);
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var root = json.RootElement;
        return new(root.GetProperty("uploadTotal").GetInt64(), root.GetProperty("downloadTotal").GetInt64(), root.GetProperty("connections").ValueKind == JsonValueKind.Array ? root.GetProperty("connections").GetArrayLength() : 0);
    }

    public async Task<int?> MeasureDelayAsync(CancellationToken ct)
    {
        var api = _api;
        if (api is null) return null;
        using var response = await api.GetAsync("proxies/proxy/delay?timeout=3500&url=" + Uri.EscapeDataString("https://cp.cloudflare.com/generate_204"), ct);
        if (!response.IsSuccessStatusCode) return null;
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return json.RootElement.TryGetProperty("delay", out var delay) ? delay.GetInt32() : null;
    }

    public async Task StopAsync()
    {
        _runningId = null;
        _api?.Dispose(); _api = null;
        // Stop the TUN first so the host's physical routes are restored before the AWG gateway exits.
        for (var i = _processes.Count - 1; i >= 0; i--)
        {
            var process = _processes[i];
            try { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); } }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or TimeoutException) { }
            finally { process.Dispose(); }
        }
        _processes.Clear();
    }

    private static int FreePort()
    {
        var tcp = new TcpListener(IPAddress.Loopback, 0); tcp.Start();
        try { return ((IPEndPoint)tcp.LocalEndpoint).Port; } finally { tcp.Stop(); }
    }

    private static string PhysicalDnsServer()
    {
        // Use the physical network's DNS for direct/local domains, before installing TUN routes.
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback && n.Name != "Tiho"))
        {
            var properties = nic.GetIPProperties();
            if (!properties.GatewayAddresses.Any(g => !g.Address.Equals(IPAddress.Any) && !g.Address.Equals(IPAddress.IPv6Any))) continue;
            var dns = properties.DnsAddresses.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip));
            if (dns is not null) return dns.ToString();
        }
        return "77.88.8.8";
    }

    public async ValueTask DisposeAsync() { await StopAsync(); _job.Dispose(); }
}
