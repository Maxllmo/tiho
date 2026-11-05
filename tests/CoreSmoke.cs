using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using Tiho.Models;
using Tiho.Services;

internal static class CoreSmoke
{
    // Starts the shipped core and performs a real DNS lookup and SOCKS request.
    // The TUN inbound is replaced by loopback mixed, so tests never change host routes.
    public static async Task RunAsync(string executable)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(35));
        var ct = timeout.Token;
        using var dns = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var dnsPort = ((IPEndPoint)dns.Client.LocalEndPoint!).Port;
        var dnsRequests = 0;
        var dnsLoop = Task.Run(async () =>
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var packet = await dns.ReceiveAsync(ct);
                    var query = packet.Buffer;
                    if (query.Length < 17) continue;
                    Interlocked.Increment(ref dnsRequests);
                    var position = 12;
                    while (position < query.Length && query[position] != 0) position += query[position] + 1;
                    if (position + 5 > query.Length) continue;
                    var end = position + 5;
                    var isA = query[position + 1] == 0 && query[position + 2] == 1;
                    var response = new List<byte>(query[..end]);
                    response[2] = 0x81; response[3] = 0x80;
                    response[6] = 0; response[7] = (byte)(isA ? 1 : 0);
                    response[8] = response[9] = response[10] = response[11] = 0;
                    if (isA) response.AddRange(new byte[] { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1 });
                    await dns.SendAsync(response.ToArray(), packet.RemoteEndPoint, ct);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        }, ct);
        var echo = new TcpListener(IPAddress.Loopback, 0); echo.Start();
        var echoPort = ((IPEndPoint)echo.LocalEndpoint).Port;
        var echoLoop = Task.Run(async () =>
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var socket = await echo.AcceptTcpClientAsync(ct);
                    _ = Task.Run(async () =>
                    {
                        using (socket)
                        {
                            var stream = socket.GetStream(); var buffer = new byte[1024];
                            try { var n = await stream.ReadAsync(buffer, ct); await stream.WriteAsync(buffer.AsMemory(0, n), ct); }
                            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
                        }
                    }, ct);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        }, ct);
        try
        {
            foreach (var mode in new[] { "AmneziaWG", "HTTP", "SOCKS5" })
            {
                var profile = new ServerProfile { Name = "Runtime test", Protocol = mode, Host = "127.0.0.1", Port = 10800 };
                var config = new AppConfig { Profiles = new() { profile }, ActiveProfileId = profile.Id, DirectDomains = new() { "direct.tiho.test" } };
                var apiPort = FreePort(); var mixedPort = FreePort();
                while (mixedPort == apiPort) mixedPort = FreePort();
                var json = TunnelConfig.Build(config, 10800, apiPort, "smoke-token", Path.GetFullPath("Tiho/Assets/Rules"), new[] { "127.0.0.1" }, "127.0.0.1");
                json["dns"]!["servers"]![0]!["server_port"] = dnsPort;
                json["inbounds"] = new JsonArray(new JsonObject { ["type"] = "mixed", ["tag"] = "tun-in", ["listen"] = "127.0.0.1", ["listen_port"] = mixedPort });
                // Allow loopback fixtures to work independently of the host's physical default interface.
                json["route"]!["auto_detect_interface"] = false;
                if (mode == "AmneziaWG")
                {
                    var broken = json.DeepClone(); broken["dns"]!["servers"]![0]!["detour"] = "direct";
                    using var rejected = Start(executable, broken.ToJsonString());
                    var rejectedError = rejected.StandardError.ReadToEndAsync(ct);
                    var rejectedOutput = rejected.StandardOutput.ReadToEndAsync(ct);
                    await rejected.WaitForExitAsync(ct);
                    var error = await rejectedError + await rejectedOutput;
                    if (rejected.ExitCode == 0 || !error.Contains("detour to an empty direct outbound", StringComparison.Ordinal))
                        throw new Exception("The startup regression was not reproduced: " + error);
                    Console.WriteLine("PASS actual core reproduces the reported DNS detour startup failure");
                }
                using var core = Start(executable, json.ToJsonString());
                var stderr = core.StandardError.ReadToEndAsync(); var stdout = core.StandardOutput.ReadToEndAsync();
                try
                {
                    using var api = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(1) };
                    api.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "smoke-token");
                    var ready = false;
                    for (var attempt = 0; attempt < 100; attempt++)
                    {
                        if (core.HasExited) throw new Exception("Core failed during startup: " + await stderr + await stdout);
                        try { using var response = await api.GetAsync($"http://127.0.0.1:{apiPort}/connections", ct); ready = response.IsSuccessStatusCode; } catch (HttpRequestException) { }
                        if (ready) break;
                        await Task.Delay(75, ct);
                    }
                    if (!ready) throw new Exception("Core API did not become ready");
                    var before = Volatile.Read(ref dnsRequests);
                    using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, mixedPort, ct);
                    var stream = client.GetStream();
                    await stream.WriteAsync(new byte[] { 5, 1, 0 }, ct);
                    var greeting = new byte[2]; await stream.ReadExactlyAsync(greeting, ct);
                    if (!greeting.SequenceEqual(new byte[] { 5, 0 })) throw new Exception("Invalid SOCKS greeting");
                    var domain = Encoding.ASCII.GetBytes("direct.tiho.test");
                    var request = new List<byte> { 5, 1, 0, 3, (byte)domain.Length }; request.AddRange(domain);
                    request.Add((byte)(echoPort >> 8)); request.Add((byte)echoPort);
                    await stream.WriteAsync(request.ToArray(), ct);
                    var header = new byte[4]; await stream.ReadExactlyAsync(header, ct);
                    if (header[1] != 0) throw new Exception("Direct DNS/SOCKS connection failed: " + header[1]);
                    var addressLength = header[3] == 1 ? 4 : header[3] == 4 ? 16 : stream.ReadByte();
                    await stream.ReadExactlyAsync(new byte[addressLength + 2], ct);
                    var message = Encoding.ASCII.GetBytes("Tiho DNS runtime check");
                    await stream.WriteAsync(message, ct);
                    var received = new byte[message.Length]; await stream.ReadExactlyAsync(received, ct);
                    if (!message.SequenceEqual(received)) throw new Exception("Direct TCP payload mismatch");
                    if (Volatile.Read(ref dnsRequests) <= before) throw new Exception("Direct DNS server did not receive the lookup");
                    Console.WriteLine($"PASS {mode}: actual core startup, authenticated API, direct DNS lookup and TCP relay");
                }
                finally
                {
                    if (!core.HasExited) core.Kill(entireProcessTree: true);
                    await core.WaitForExitAsync(); await Task.WhenAll(stderr, stdout);
                }
            }
        }
        finally
        {
            timeout.Cancel(); echo.Stop();
            await Task.WhenAll(dnsLoop, echoLoop);
        }
    }

    private static Process Start(string executable, string json)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false)
        };
        start.ArgumentList.Add("--disable-color"); start.ArgumentList.Add("run"); start.ArgumentList.Add("-c"); start.ArgumentList.Add("stdin");
        var process = Process.Start(start) ?? throw new Exception("Core process did not start");
        process.StandardInput.Write(json); process.StandardInput.Close(); return process;
    }
    private static int FreePort()
    {
        var tcp = new TcpListener(IPAddress.Loopback, 0); tcp.Start();
        try { return ((IPEndPoint)tcp.LocalEndpoint).Port; } finally { tcp.Stop(); }
    }
}
