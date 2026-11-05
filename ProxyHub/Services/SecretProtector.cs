using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace ProxyHub.Services;

public static class SecretProtector
{
    private const string Prefix = "dpapi:";
    private static readonly HashSet<string> Fields = new(StringComparer.OrdinalIgnoreCase)
    { "Password", "WireGuardConfig", "ShareUri", "SubscriptionUrl", "Url" };

    public static string Transform(string json, bool protect)
    {
        var root = JsonNode.Parse(json) ?? throw new InvalidOperationException("Пустой файл настроек.");
        Visit(root, protect);
        return root.ToJsonString(new() { WriteIndented = true });
    }
    private static void Visit(JsonNode node, bool protect)
    {
        if (node is JsonArray array) { foreach (var item in array) if (item is not null) Visit(item, protect); return; }
        if (node is not JsonObject obj) return;
        foreach (var (name, value) in obj.ToList())
        {
            if (Fields.Contains(name) && value is JsonValue text && text.TryGetValue<string>(out var s) && !string.IsNullOrEmpty(s))
            {
                if (protect && !s.StartsWith(Prefix, StringComparison.Ordinal))
                    obj[name] = Prefix + Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(s), null, DataProtectionScope.CurrentUser));
                else if (!protect && s.StartsWith(Prefix, StringComparison.Ordinal))
                    obj[name] = Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(s[Prefix.Length..]), null, DataProtectionScope.CurrentUser));
            }
            else if (value is not null) Visit(value, protect);
        }
    }
}
