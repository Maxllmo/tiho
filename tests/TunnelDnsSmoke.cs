using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Tiho.Models;
using Tiho.Services;

internal static class TunnelDnsSmoke
{
    // A physical resolver poisons foreign names. The protected resolver is reachable
    // only through a second real sing-box process; all fixtures stay on loopback.
    public static async Task RunAsync(string executable)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var ct = timeout.Token;
        using var key = RSA.Create(2048);
        var certificateRequest = new CertificateRequest("CN=dns.tiho.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("dns.tiho.test");
        certificateRequest.CertificateExtensions.Add(san.Build());
        using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        var physicalNames = new ConcurrentBag<string>();
        var protectedNames = new ConcurrentBag<string>();
        using var physical = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var doh = new TcpListener(IPAddress.Loopback, 0); doh.Start();
        var echo = new TcpListener(IPAddress.Loopback, 0); echo.Start();
        var tasks = new ConcurrentBag<Task>();
        var physicalLoop = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    var packet = await physical.ReceiveAsync(ct);
                    physicalNames.Add(Name(packet.Buffer));
                    await physical.SendAsync(Answer(packet.Buffer, Name(packet.Buffer) == "direct.tiho.test"), packet.RemoteEndPoint, ct);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        });
        var dohLoop = AcceptAsync(doh, async stream =>
        {
            using var tls = new SslStream(stream);
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, ct);
            var header = new List<byte>();
            while (header.Count < 16384)
            {
                var b = new byte[1]; await tls.ReadExactlyAsync(b, ct); header.Add(b[0]);
                if (header.Count >= 4 && header.TakeLast(4).SequenceEqual(new byte[] { 13, 10, 13, 10 })) break;
            }
            var lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n");
            if (!lines[0].StartsWith("POST /dns-query ")) throw new Exception("Expected DNS-over-HTTPS POST");
            var length = int.Parse(lines.Single(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)).Split(':')[1]);
            var query = new byte[length]; await tls.ReadExactlyAsync(query, ct);
            protectedNames.Add(Name(query));
            var answer = Answer(query, true);
            await tls.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {answer.Length}\r\nConnection: close\r\n\r\n"), ct);
            await tls.WriteAsync(answer, ct);
        }, tasks, ct);
        var echoLoop = AcceptAsync(echo, async stream =>
        {
            var buffer = new byte[1024]; var n = await stream.ReadAsync(buffer, ct);
            await stream.WriteAsync(buffer.AsMemory(0, n), ct);
        }, tasks, ct);
        try
        {
            foreach (var mode in new[] { "AmneziaWG", "SOCKS5", "HTTP" })
            foreach (var bypass in new[] { true, false })
            {
                var proxyPort = FreePort();
                using var upstream = Start(executable, new JsonObject
                {
                    ["log"] = new JsonObject { ["level"] = "error" },
                    ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "mixed", ["listen"] = "127.0.0.1", ["listen_port"] = proxyPort }),
                    ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "fixture" })
                });
                var upstreamError = upstream.StandardError.ReadToEndAsync(); var upstreamOutput = upstream.StandardOutput.ReadToEndAsync();
                try
                {
                    await WaitForPortAsync(upstream, proxyPort, ct);
                    foreach (var dualStack in mode == "AmneziaWG" ? new[] { false, true } : new[] { true })
                    {
                        var profile = new ServerProfile { Protocol = mode, Host = "127.0.0.1", Port = proxyPort,
                            WireGuardConfig = "[Interface]\nAddress = 10.77.0.2/32" + (dualStack ? ", fd00::2/128" : "") + "\n[Peer]\n" };
                        var config = new AppConfig { Profiles = new() { profile }, BypassRussia = bypass, DirectDomains = new() { "direct.tiho.test" } };
                        var mixedPort = FreePort(); var apiPort = FreePort();
                        var json = TunnelConfig.Build(config, proxyPort, apiPort, "dns-test", Path.GetFullPath("Tiho/Assets/Rules"), new[] { "127.0.0.1" }, "127.0.0.1");
                        json["route"]!["auto_detect_interface"] = false;
                        json["inbounds"] = new JsonArray(new JsonObject { ["type"] = "mixed", ["listen"] = "127.0.0.1", ["listen_port"] = mixedPort });
                        json["dns"]!["servers"]![0]!["server_port"] = ((IPEndPoint)physical.Client.LocalEndPoint!).Port;
                        var protectedDns = json["dns"]!["servers"]![1]!;
                        // Preserve the production transport and detour. Replace only the resolver endpoint and trust root.
                        protectedDns["server"] = "127.0.0.1";
                        protectedDns["server_port"] = ((IPEndPoint)doh.LocalEndpoint).Port;
                        if (protectedDns["tls"] is JsonObject tls)
                        {
                            tls["server_name"] = "dns.tiho.test";
                            tls["certificate"] = certificate.ExportCertificatePem();
                        }
                        using var core = Start(executable, json);
                        var error = core.StandardError.ReadToEndAsync(); var output = core.StandardOutput.ReadToEndAsync();
                        try
                        {
                            await WaitForPortAsync(core, mixedPort, ct);
                            var foreign = await QueryAsync(mixedPort, "foreign.tiho.test", 1, ct);
                            if (foreign[7] != 1 || !foreign.TakeLast(4).SequenceEqual(new byte[] { 127, 0, 0, 1 }))
                                throw new Exception($"{mode}: foreign DNS used the poisoned physical resolver");
                            var aaaa = await QueryAsync(mixedPort, "foreign.tiho.test", 28, ct);
                            if (aaaa[7] != (dualStack ? 1 : 0)) throw new Exception($"{mode}: unusable IPv6 advertised, or dual-stack IPv6 lost");
                            var direct = await QueryAsync(mixedPort, "direct.tiho.test", 28, ct);
                            if (direct[7] != 1) throw new Exception("Local/direct IPv6 must remain available");
                            // Test destination-domain routing too, including when country bypass is disabled.
                            using var client = await ConnectAsync(mixedPort, "foreign.tiho.test", ((IPEndPoint)echo.LocalEndpoint).Port, ct);
                            var message = Encoding.ASCII.GetBytes("protected DNS and proxy TCP");
                            await client.GetStream().WriteAsync(message, ct);
                            var received = new byte[message.Length]; await client.GetStream().ReadExactlyAsync(received, ct);
                            if (!received.SequenceEqual(message)) throw new Exception("Proxied TCP payload mismatch");
                            Console.WriteLine($"PASS {mode}, Russia bypass={bypass}, dual stack={dualStack}: protected DNS, AAAA policy, direct IPv6 and proxied TCP");
                        }
                        finally
                        {
                            if (!core.HasExited) core.Kill(true);
                            await core.WaitForExitAsync();
                            var logs = await error + await output;
                            if (logs.Contains("FATAL", StringComparison.Ordinal) || logs.Contains("ERROR", StringComparison.Ordinal)) Console.Error.WriteLine(logs);
                        }
                    }
                }
                finally
                {
                    if (!upstream.HasExited) upstream.Kill(true);
                    await upstream.WaitForExitAsync(); await Task.WhenAll(upstreamError, upstreamOutput);
                }
            }
            if (physicalNames.Any(n => n == "foreign.tiho.test")) throw new Exception("Foreign DNS leaked to the physical resolver");
            if (!protectedNames.Contains("foreign.tiho.test") || !physicalNames.Contains("direct.tiho.test")) throw new Exception("DNS fixtures were not exercised");
        }
        finally
        {
            timeout.Cancel(); doh.Stop(); echo.Stop();
            await Task.WhenAll(physicalLoop, dohLoop, echoLoop);
            await Task.WhenAll(tasks);
        }
    }

    private static async Task AcceptAsync(TcpListener listener, Func<NetworkStream, Task> handle, ConcurrentBag<Task> tasks, CancellationToken ct)
    {
        try
        {
            while (true)
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                tasks.Add(Task.Run(async () =>
                {
                    using (client)
                    {
                        try { await handle(client.GetStream()); }
                        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
                        catch (EndOfStreamException) { } // Readiness probes close without a request.
                        catch (IOException) when (ct.IsCancellationRequested) { }
                    }
                }));
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
    }

    private static string Name(byte[] query)
    {
        var labels = new List<string>(); var p = 12;
        while (query[p] != 0) { var n = query[p++]; labels.Add(Encoding.ASCII.GetString(query, p, n)); p += n; }
        return string.Join('.', labels);
    }

    private static byte[] Answer(byte[] query, bool healthy)
    {
        var p = 12; while (query[p] != 0) p += query[p] + 1;
        var ipv6 = query[p + 2] == 28;
        var answer = new List<byte>(query[..(p + 5)]);
        answer[2] = 0x81; answer[3] = 0x80; answer[6] = 0; answer[7] = 1;
        answer[8] = answer[9] = answer[10] = answer[11] = 0;
        var ip = IPAddress.Parse(ipv6 ? "::1" : healthy ? "127.0.0.1" : "192.0.2.123").GetAddressBytes();
        answer.AddRange(new byte[] { 0xc0, 0x0c, 0, (byte)(ipv6 ? 28 : 1), 0, 1, 0, 0, 0, 30, 0, (byte)ip.Length });
        answer.AddRange(ip); return answer.ToArray();
    }

    private static async Task<byte[]> QueryAsync(int port, string name, byte type, CancellationToken ct)
    {
        using var client = await ConnectAsync(port, "127.0.0.1", 53, ct);
        var query = new List<byte> { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.Split('.')) { query.Add((byte)label.Length); query.AddRange(Encoding.ASCII.GetBytes(label)); }
        query.AddRange(new byte[] { 0, 0, type, 0, 1 });
        var stream = client.GetStream();
        await stream.WriteAsync(new byte[] { (byte)(query.Count >> 8), (byte)query.Count }.Concat(query).ToArray(), ct);
        var size = new byte[2]; await stream.ReadExactlyAsync(size, ct);
        var response = new byte[(size[0] << 8) | size[1]]; await stream.ReadExactlyAsync(response, ct);
        if (response.Length < 12 || (response[3] & 15) != 0) throw new Exception("DNS query failed");
        return response;
    }

    private static async Task<TcpClient> ConnectAsync(int port, string host, int targetPort, CancellationToken ct)
    {
        var client = new TcpClient();
        try
        {
            await client.ConnectAsync(IPAddress.Loopback, port, ct); var stream = client.GetStream();
            await stream.WriteAsync(new byte[] { 5, 1, 0 }, ct);
            var greeting = new byte[2]; await stream.ReadExactlyAsync(greeting, ct);
            if (!greeting.SequenceEqual(new byte[] { 5, 0 })) throw new Exception("SOCKS greeting failed");
            var domain = Encoding.ASCII.GetBytes(host);
            var request = new List<byte> { 5, 1, 0, 3, (byte)domain.Length }; request.AddRange(domain);
            request.Add((byte)(targetPort >> 8)); request.Add((byte)targetPort);
            await stream.WriteAsync(request.ToArray(), ct);
            var header = new byte[4]; await stream.ReadExactlyAsync(header, ct);
            if (header[1] != 0) throw new Exception("SOCKS connect failed: " + header[1]);
            var length = header[3] == 1 ? 4 : header[3] == 4 ? 16 : stream.ReadByte();
            await stream.ReadExactlyAsync(new byte[length + 2], ct); return client;
        }
        catch { client.Dispose(); throw; }
    }

    private static Process Start(string executable, JsonObject json)
    {
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardError = true, RedirectStandardOutput = true };
        foreach (var arg in new[] { "--disable-color", "run", "-c", "stdin" }) start.ArgumentList.Add(arg);
        var process = Process.Start(start) ?? throw new Exception("Core failed to start");
        process.StandardInput.Write(json.ToJsonString()); process.StandardInput.Close(); return process;
    }

    private static async Task WaitForPortAsync(Process process, int port, CancellationToken ct)
    {
        for (var i = 0; i < 100; i++)
        {
            if (process.HasExited) throw new Exception("Fixture core exited: " + await process.StandardError.ReadToEndAsync(ct));
            try { using var probe = new TcpClient(); await probe.ConnectAsync(IPAddress.Loopback, port, ct); return; }
            catch (SocketException) { await Task.Delay(50, ct); }
        }
        throw new Exception("Core did not become ready");
    }
    private static int FreePort() { var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); try { return ((IPEndPoint)listener.LocalEndpoint).Port; } finally { listener.Stop(); } }
}
