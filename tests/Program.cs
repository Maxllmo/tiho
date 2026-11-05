using System.Text.Json;
using ProxyHub.Models;
using ProxyHub.Services;

static void Check(bool condition, string message) { if (!condition) throw new Exception(message); Console.WriteLine("PASS " + message); }
var key = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray());
var conf = $"[Interface]\nPrivateKey = {key}\nAddress = 10.77.0.2/32\nJc = 4\nS1 = 16\nS2 = 16\n[Peer]\nPublicKey = {key}\nEndpoint = 127.0.0.1:43798\nAllowedIPs = 0.0.0.0/0\n";
var profile = AmneziaConfigImporter.Parse(conf, "Test AWG");
Check(profile.IsAmnezia && profile.Port == 43798 && profile.WireGuardConfig == conf, "Import preserves AWG parameters and extracts endpoint");
Check(AmneziaConfigImporter.Parse(conf.Replace("10.77.0.2/32", "10.77.0.2/24"), "client").IsConfigured, "Client addresses with host bits are valid");
try { AmneziaConfigImporter.Parse(conf + "\n[Peer]\n", "bad"); throw new Exception("Multiple peers accepted"); } catch (InvalidOperationException) { Console.WriteLine("PASS server/multi-peer configs rejected"); }
try { AmneziaConfigImporter.Parse(conf.Replace("PrivateKey = " + key, "PrivateKey = invalid"), "bad"); throw new Exception("Invalid key accepted"); } catch (InvalidOperationException) { Console.WriteLine("PASS invalid keys rejected"); }
var config = new AppConfig { Profiles = new() { profile }, ActiveProfileId = profile.Id, ExcludedApps = new() { @"C:\Games\game.exe", "browser.exe" }, DirectDomains = new() { "Пример.рф", "example.com" } };
var rulesDir = Path.GetFullPath("ProxyHub/Assets/Rules");
var built = TunnelConfig.Build(config, 10800, 19090, "test-only-token", rulesDir, new[] { "87.121.114.149", "2001:db8::1" });
var rules = built["route"]!["rules"]!.AsArray();
Check(rules[1]!["process_path"]![0]!.GetValue<string>() == @"C:\Games\game.exe", "Application exclusions precede DNS and sniffing");
Check(rules.Any(r => r?["rule_set"]?.ToJsonString().Contains("ru-domains") == true) && rules.Any(r => r?["rule_set"]?.ToJsonString().Contains("ru-ip") == true), "Russia bypass includes domains and GeoIP");
Check(built["route"]!["final"]!.GetValue<string>() == "proxy", "Unmatched destinations use VPN");
Check(built["route"]!["rules"]!.AsArray().Any(r => r?["domain_suffix"]?.ToJsonString().Contains("local") == true), "Local network domains remain direct independently of country bypass");
Check(built["inbounds"]![0]!["auto_route"]!.GetValue<bool>() && built["inbounds"]![0]!["strict_route"]!.GetValue<bool>(), "TUN captures IPv4/IPv6 with strict routing");
Check(built["inbounds"]![0]!["route_exclude_address"]!.ToJsonString().Contains("87.121.114.149/32"), "VPN endpoint excluded from TUN to avoid loops");
Check(TunnelConfig.NormalizeDomain("https://пример.рф/path") == "xn--e1afmkfd.xn--p1ai", "IDN and URL domain normalization");
var outputDir = Path.GetFullPath("work"); Directory.CreateDirectory(outputDir);
File.WriteAllText(Path.Combine(outputDir, "test-tun-config.json"), built.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
config.BypassRussia = false;
var full = TunnelConfig.Build(config, 10800, 19090, "test-only-token", rulesDir, new[] { "127.0.0.1" });
Check(!full["route"]!["rules"]!.AsArray().Any(r => r?["rule_set"] is not null), "Russia bypass can be disabled while preserving app exceptions");
var proxy = new ServerProfile { Name = "Squid", Protocol = "HTTP", Host = "127.0.0.1", Port = 3128 };
config.Profiles = new() { proxy }; config.ActiveProfileId = proxy.Id;
var http = TunnelConfig.Build(config, 10800, 19090, "test-only-token", rulesDir, new[] { "127.0.0.1" });
Check(http["route"]!["rules"]!.AsArray().Any(r => r?["network"]?.GetValue<string>() == "udp" && r?["action"]?.GetValue<string>() == "reject"), "Squid never silently leaks unsupported UDP directly");
File.WriteAllText(Path.Combine(outputDir, "test-http-config.json"), http.ToJsonString());
var usagePath = Path.Combine(outputDir, "test-usage.json"); if (File.Exists(usagePath)) File.Delete(usagePath);
var usage = new UsageTracker(usagePath); usage.Begin(); usage.Sample(100, 200); usage.Sample(150, 300);
Check(usage.SessionUpload == 150 && usage.SessionDownload == 300, "Traffic counters accumulate deltas without double counting");
usage.Pause(); usage.CoreRestarted(); usage.Sample(20, 40);
Check(usage.SessionUpload == 170 && usage.SessionDownload == 340, "Automatic reconnect handles reset core counters");
usage.End(); var loaded = new UsageTracker(usagePath);
Check(loaded.TotalUpload == 170 && loaded.TotalDownload == 340 && usage.TotalDownload == 340, "Lifetime totals persist and committing a session does not double count");
usage.Begin(); usage.Sample(10, 20); usage.End();
Check(new UsageTracker(usagePath).TotalDownload == 360, "A new session adds to lifetime totals");
Check(UsageTracker.Duration(TimeSpan.FromHours(27)) == "1 д 03:00:00", "Duration does not wrap after 24 hours");
Check(UsageTracker.Gigabytes(1_000_000_000).StartsWith("1"), "Decimal gigabytes use one billion bytes");
Console.WriteLine("All Tiho checks passed.");
