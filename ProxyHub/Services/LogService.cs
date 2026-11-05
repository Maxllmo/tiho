using System.Collections.ObjectModel;
using System.Text.RegularExpressions;
using ProxyHub.Models;

namespace ProxyHub.Services;

// Intentionally session-only: no log files, crash dumps or automatic exports.
public sealed class LogService
{
    private const int MaxLines = 1500;
    public ObservableCollection<LogEntry> All { get; } = new();
    public void Info(string source, string message) => Add("INFO", source, message);
    public void Bypass(string source, string message) => Add("DIRECT", source, message);
    public void Error(string source, string message) => Add("ERROR", source, message);
    public void Sys(string message) => Add("SYS", "Tiho", message);
    public void Clear() => OnUi(All.Clear);
    private void Add(string level, string source, string message)
    {
        message = Regex.Replace(message, @"(?i)(private_?key|preshared_?key|header_?protection_?key|password)\s*[=:]\s*[^\s,;]+", "$1=[скрыто]");
        var entry = new LogEntry { Level = level, Source = source, Message = message };
        OnUi(() => { All.Add(entry); while (All.Count > MaxLines) All.RemoveAt(0); });
    }
    private static void OnUi(Action action)
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess()) action(); else dispatcher.BeginInvoke(action);
    }
}
