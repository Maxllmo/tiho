using System.Text.Json.Nodes;
using ProxyHub.Models;

namespace ProxyHub.Services;

public static class OutboundConfig
{
    public static JsonObject Build(ServerProfile profile)
    {
        var http = profile.Protocol.Equals("HTTP", StringComparison.OrdinalIgnoreCase);
        var outbound = new JsonObject
        {
            ["type"] = http ? "http" : "socks", ["tag"] = "proxy", ["server"] = profile.Host, ["server_port"] = profile.Port
        };
        if (!http) outbound["version"] = "5";
        if (!string.IsNullOrEmpty(profile.Username)) { outbound["username"] = profile.Username; outbound["password"] = profile.Password; }
        return outbound;
    }
}
