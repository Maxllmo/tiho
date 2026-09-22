namespace ProxyHub.Models;

public sealed class LogEntry
{
    public DateTime Time { get; init; } = DateTime.Now;
    public string Level { get; init; } = "INFO";
    public string Source { get; init; } = "SYS";
    public string Message { get; init; } = "";

    public string Display => $"[{Time:HH:mm:ss}]  {Source,-4}  {Message}";
}

public sealed class HubStats
{
    public long Requests;
    public long Errors;
    public long BytesUp;
    public long BytesDown;
    public int Active;
    public string LastError = "";

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:0.0} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / 1024.0 / 1024.0:0.0} MB";
        return $"{bytes / 1024.0 / 1024.0 / 1024.0:0.00} GB";
    }
}
