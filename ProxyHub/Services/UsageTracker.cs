using System.Diagnostics;
using System.Text.Json;

namespace ProxyHub.Services;

public sealed class UsageTracker
{
    private sealed class History { public long Upload { get; set; } public long Download { get; set; } public double Seconds { get; set; } }
    private readonly string _path;
    private readonly Stopwatch _connection = new();
    private History _history = new();
    private long _lastUp, _lastDown;
    private double _lastSample;
    private bool _committed = true;
    public long SessionUpload { get; private set; }
    public long SessionDownload { get; private set; }
    public double UploadSpeed { get; private set; }
    public double DownloadSpeed { get; private set; }
    public long TotalUpload => _history.Upload + (_committed ? 0 : SessionUpload);
    public long TotalDownload => _history.Download + (_committed ? 0 : SessionDownload);
    public TimeSpan ConnectedTime => _connection.Elapsed;
    public TimeSpan TotalTime => TimeSpan.FromSeconds(_history.Seconds) + (_committed ? TimeSpan.Zero : ConnectedTime);

    public UsageTracker(string path)
    {
        _path = path;
        if (File.Exists(path))
        {
            try { _history = JsonSerializer.Deserialize<History>(File.ReadAllText(path)) ?? new(); }
            catch (JsonException) { File.Copy(path, path + ".damaged-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss"), true); }
        }
    }

    public void Begin()
    {
        SessionUpload = SessionDownload = 0; _lastUp = _lastDown = 0;
        UploadSpeed = DownloadSpeed = 0; _lastSample = 0; _committed = false;
        _connection.Restart();
    }

    public void Sample(long upload, long download)
    {
        var now = _connection.Elapsed.TotalSeconds;
        var up = Math.Max(0, upload - _lastUp); var down = Math.Max(0, download - _lastDown);
        var seconds = now - _lastSample;
        if (seconds > 0) { UploadSpeed = up / seconds; DownloadSpeed = down / seconds; }
        SessionUpload += up; SessionDownload += down;
        _lastUp = upload; _lastDown = download; _lastSample = now;
    }

    // On an automatic reconnect the app session continues, but core counters restart from zero.
    public void CoreRestarted() { _lastUp = _lastDown = 0; _lastSample = _connection.Elapsed.TotalSeconds; UploadSpeed = DownloadSpeed = 0; _connection.Start(); }
    public void Pause() { _connection.Stop(); UploadSpeed = DownloadSpeed = 0; }
    public void End()
    {
        if (_committed) return;
        _connection.Stop(); Save();
        _history.Upload += SessionUpload; _history.Download += SessionDownload; _history.Seconds += _connection.Elapsed.TotalSeconds;
        _committed = true; UploadSpeed = DownloadSpeed = 0;
    }
    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var snapshot = new History { Upload = TotalUpload, Download = TotalDownload, Seconds = TotalTime.TotalSeconds };
        var temp = _path + ".tmp"; File.WriteAllText(temp, JsonSerializer.Serialize(snapshot)); File.Move(temp, _path, true);
    }
    public static string Duration(TimeSpan span) => span.TotalDays >= 1 ? $"{(int)span.TotalDays} д {span:hh\\:mm\\:ss}" : $"{(int)span.TotalHours:00}:{span:mm\\:ss}";
    public static string Gigabytes(long bytes) => (bytes / 1_000_000_000d).ToString("0.00", System.Globalization.CultureInfo.CurrentCulture) + " ГБ";
    public static string Megabits(double bytesPerSecond) => (Math.Max(0, bytesPerSecond) * 8 / 1_000_000).ToString("0.0", System.Globalization.CultureInfo.CurrentCulture) + " Мбит/с";
}
