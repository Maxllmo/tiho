using System.Net.Http;
using ProxyHub.Models;

namespace ProxyHub.Services;

public static class SubscriptionService
{
    public static async Task<IReadOnlyList<ServerProfile>> FetchAsync(string url, CancellationToken ct)
    {
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            throw new InvalidOperationException("Укажите http(s) ссылку подписки.");

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(25) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("ProxyHub/1.1");
        var bytes = await http.GetByteArrayAsync(uri, ct);
        var text = Encoding.UTF8.GetString(bytes);
        var profiles = ShareLinkParser.ParseMany(text);
        if (profiles.Count == 0)
            throw new InvalidOperationException("Подписка не содержит известных ссылок (vless/vmess/trojan/ss/hy2/socks).");

        foreach (var profile in profiles)
            profile.SubscriptionUrl = uri.ToString();
        return profiles;
    }
}
