namespace Tiho.Models;

public sealed class LogEntry
{
    public DateTime Time { get; init; } = DateTime.Now;
    public string Level { get; init; } = "INFO";
    public string Source { get; init; } = "SYS";
    public string Message { get; init; } = "";

    public string Display => $"[{Time:HH:mm:ss}]  {Source,-4}  {Message}";
}
