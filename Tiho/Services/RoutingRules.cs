using System.Net.Http;
using System.Text.Json.Nodes;

namespace Tiho.Services;

public static class RoutingRules
{
    public static string DirectoryPath { get; } = Path.Combine(ConfigStore.RootDir, "rules");
    public static void EnsureBundled()
    {
        Directory.CreateDirectory(DirectoryPath);
        foreach (var name in new[] { "ru-domains.json", "ru-ip.json" })
        {
            var target = Path.Combine(DirectoryPath, name);
            if (!File.Exists(target)) File.Copy(Path.Combine(AppContext.BaseDirectory, "Assets", "Rules", name), target);
        }
    }

    public static async Task UpdateAsync(CancellationToken ct)
    {
        using var http = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(30) };
        var domainsTask = http.GetStringAsync("https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ru.list", ct);
        var ipTask = http.GetStringAsync("https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/ru.txt", ct);
        await Task.WhenAll(domainsTask, ipTask);
        var exact = new JsonArray(); var suffix = new JsonArray();
        foreach (var raw in (await domainsTask).Split('\n'))
        {
            var line = raw.Trim(); if (line.Length == 0 || line.StartsWith('#')) continue;
            if (line.StartsWith("+.")) suffix.Add(TunnelConfig.NormalizeDomain(line[2..]));
            else exact.Add(TunnelConfig.NormalizeDomain(line));
        }
        var ips = new JsonArray();
        foreach (var raw in (await ipTask).Split('\n'))
        {
            var line = raw.Trim(); if (line.Length == 0 || line.StartsWith('#')) continue;
            if (!IPNetwork.TryParse(line, out _)) throw new InvalidOperationException("Источник вернул некорректный IP-список.");
            ips.Add(line);
        }
        if (exact.Count + suffix.Count < 100 || ips.Count < 1000) throw new InvalidOperationException("Списки неполные; сохранены предыдущие правила.");
        Directory.CreateDirectory(DirectoryPath);
        var domainJson = new JsonObject { ["version"] = 3, ["rules"] = new JsonArray(new JsonObject { ["domain"] = exact, ["domain_suffix"] = suffix }) };
        var ipJson = new JsonObject { ["version"] = 3, ["rules"] = new JsonArray(new JsonObject { ["ip_cidr"] = ips }) };
        await File.WriteAllTextAsync(Path.Combine(DirectoryPath, "ru-domains.json.tmp"), domainJson.ToJsonString(), ct);
        await File.WriteAllTextAsync(Path.Combine(DirectoryPath, "ru-ip.json.tmp"), ipJson.ToJsonString(), ct);
        ct.ThrowIfCancellationRequested();
        File.Move(Path.Combine(DirectoryPath, "ru-domains.json.tmp"), Path.Combine(DirectoryPath, "ru-domains.json"), true);
        File.Move(Path.Combine(DirectoryPath, "ru-ip.json.tmp"), Path.Combine(DirectoryPath, "ru-ip.json"), true);
    }
}
