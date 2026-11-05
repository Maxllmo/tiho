using System.Text.Json;
using System.Text.Json.Nodes;
using ProxyHub.Models;

namespace ProxyHub.Services;

public static class TunnelConfig
{
    public static JsonObject Build(AppConfig config, int socksPort, int apiPort, string apiSecret,
        string rulesDir, IEnumerable<string> endpointAddresses, string directDnsServer = "77.88.8.8")
    {
        var profile = config.ActiveProfile ?? throw new InvalidOperationException("Добавьте сервер.");
        var outbound = profile.IsAmnezia
            ? new JsonObject { ["type"] = "socks", ["tag"] = "proxy", ["server"] = "127.0.0.1", ["server_port"] = socksPort, ["version"] = "5" }
            : OutboundConfig.Build(profile);
        var self = new JsonArray("Tiho.exe", "tiho-awg.exe", "sing-box.exe");
        var appPaths = config.ExcludedApps.Where(IsAppPath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var appNames = config.ExcludedApps.Where(p => !IsAppPath(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var domains = config.DirectDomains.Select(NormalizeDomain).Where(s => s.Length > 0).Distinct().ToArray();
        var rules = new JsonArray();
        rules.Add(new JsonObject { ["process_name"] = self, ["action"] = "route", ["outbound"] = "direct" });
        // App exceptions come before DNS hijacking and sniffing, including their own DNS/UDP.
        if (appPaths.Length > 0) rules.Add(DirectRule("process_path", appPaths));
        if (appNames.Length > 0) rules.Add(DirectRule("process_name", appNames));
        rules.Add(new JsonObject { ["action"] = "sniff", ["timeout"] = "300ms" });
        rules.Add(new JsonObject { ["protocol"] = "dns", ["action"] = "hijack-dns" });
        rules.Add(new JsonObject { ["ip_is_private"] = true, ["action"] = "route", ["outbound"] = "direct" });
        var localDomains = new[] { "localhost", "local", "lan", "home", "internal", "corp" };
        rules.Add(DirectRule("domain_suffix", localDomains));
        if (domains.Length > 0) rules.Add(DirectRule("domain_suffix", domains));
        if (config.BypassRussia)
        {
            rules.Add(new JsonObject { ["rule_set"] = new JsonArray("ru-domains"), ["action"] = "route", ["outbound"] = "direct" });
            rules.Add(new JsonObject { ["action"] = "resolve", ["strategy"] = "prefer_ipv4" });
            rules.Add(new JsonObject { ["rule_set"] = new JsonArray("ru-ip"), ["action"] = "route", ["outbound"] = "direct" });
        }
        // Squid cannot carry UDP. Fail explicitly instead of silently leaking it to a direct route.
        if (profile.Protocol.Equals("HTTP", StringComparison.OrdinalIgnoreCase))
            rules.Add(new JsonObject { ["network"] = "udp", ["action"] = "reject" });
        var dnsRules = new JsonArray();
        dnsRules.Add(DnsRule("domain_suffix", localDomains));
        if (appPaths.Length > 0) dnsRules.Add(DnsRule("process_path", appPaths));
        if (appNames.Length > 0) dnsRules.Add(DnsRule("process_name", appNames));
        if (domains.Length > 0) dnsRules.Add(DnsRule("domain_suffix", domains));
        if (config.BypassRussia)
            dnsRules.Add(DnsRule("rule_set", new[] { "ru-domains" }));
        var excludes = new List<string> { "127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10" };
        excludes.AddRange(endpointAddresses.Select(ip => ip + (ip.Contains(':') ? "/128" : "/32")));
        return new JsonObject
        {
            ["log"] = new JsonObject { ["level"] = "info", ["timestamp"] = false, ["disabled"] = false },
            ["dns"] = new JsonObject
            {
                ["servers"] = new JsonArray
                {
                    new JsonObject { ["type"] = "udp", ["tag"] = "dns-direct", ["server"] = directDnsServer, ["server_port"] = 53, ["detour"] = "direct" },
                    new JsonObject { ["type"] = "udp", ["tag"] = "dns-tunnel", ["server"] = "1.1.1.1", ["server_port"] = 53, ["detour"] = "proxy" }
                },
                ["rules"] = dnsRules,
                ["final"] = profile.Protocol.Equals("HTTP", StringComparison.OrdinalIgnoreCase) ? "dns-direct" : "dns-tunnel",
                ["strategy"] = "prefer_ipv4", ["reverse_mapping"] = true
            },
            ["inbounds"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "tun", ["tag"] = "tun-in", ["interface_name"] = "Tiho",
                    ["address"] = new JsonArray("172.30.255.1/30", "fdfe:7469:686f::1/126"),
                ["mtu"] = 1280, ["auto_route"] = true, ["strict_route"] = true,
                    ["dns_mode"] = "hijack", ["stack"] = "mixed", ["route_exclude_address"] = Strings(excludes)
                }
            },
            ["outbounds"] = new JsonArray(outbound, new JsonObject { ["type"] = "direct", ["tag"] = "direct" }),
            ["route"] = new JsonObject
            {
                ["auto_detect_interface"] = true, ["find_process"] = true,
                ["default_domain_resolver"] = "dns-direct", ["final"] = "proxy", ["rules"] = rules,
                ["rule_set"] = new JsonArray
                {
                    LocalRuleSet("ru-domains", Path.Combine(rulesDir, "ru-domains.json")),
                    LocalRuleSet("ru-ip", Path.Combine(rulesDir, "ru-ip.json"))
                }
            },
            ["experimental"] = new JsonObject
            {
                ["clash_api"] = new JsonObject
                {
                    ["external_controller"] = $"127.0.0.1:{apiPort}", ["secret"] = apiSecret, ["default_mode"] = "rule"
                }
            }
        };
    }

    private static JsonObject LocalRuleSet(string tag, string path) => new()
    { ["type"] = "local", ["tag"] = tag, ["format"] = "source", ["path"] = path };
    private static JsonObject DirectRule(string field, IEnumerable<string> values) => new()
    { [field] = Strings(values), ["action"] = "route", ["outbound"] = "direct" };
    private static JsonObject DnsRule(string field, IEnumerable<string> values) => new()
    { [field] = Strings(values), ["action"] = "route", ["server"] = "dns-direct" };
    private static JsonArray Strings(IEnumerable<string> values) => new(values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());
    private static bool IsAppPath(string path) => Path.IsPathRooted(path) || (path.Length > 2 && char.IsLetter(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) || path.StartsWith(@"\\");

    public static string NormalizeDomain(string value)
    {
        var domain = value.Trim().TrimStart('*', '.').TrimEnd('.').ToLowerInvariant();
        if (Uri.TryCreate(domain, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host)) domain = uri.Host;
        if (domain.Contains('/') || domain.Contains(':') || domain.Any(char.IsWhiteSpace))
            throw new InvalidOperationException($"Укажите домен без пути и порта: {value}");
        return string.IsNullOrEmpty(domain) ? "" : new System.Globalization.IdnMapping().GetAscii(domain);
    }
}
