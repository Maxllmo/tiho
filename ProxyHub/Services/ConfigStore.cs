using System.Text.Json;
using ProxyHub.Models;

namespace ProxyHub.Services;

public static class ConfigStore
{
    public static string RootDir { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Tiho");
    private static string ConfigPath => Path.Combine(RootDir, "config.json");
    public static AppConfig Load()
    {
        Directory.CreateDirectory(RootDir);
        if (!File.Exists(ConfigPath)) return new AppConfig();
        var json = SecretProtector.Transform(File.ReadAllText(ConfigPath), protect: false);
        return JsonSerializer.Deserialize<AppConfig>(json) ?? throw new InvalidOperationException("Не удалось прочитать настройки Tiho.");
    }
    public static void Save(AppConfig config)
    {
        Directory.CreateDirectory(RootDir);
        var json = SecretProtector.Transform(JsonSerializer.Serialize(config), protect: true);
        var temp = ConfigPath + ".tmp";
        File.WriteAllText(temp, json); File.Move(temp, ConfigPath, true);
    }
}
