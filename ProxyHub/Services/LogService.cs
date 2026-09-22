using System.Collections.ObjectModel;
using System.Windows;
using ProxyHub.Models;

namespace ProxyHub.Services;

public sealed class LogService
{
    private const int MaxUiLines = 2500;
    private readonly object _gate = new();
    private readonly string _allFile;
    private readonly string _errFile;

    public ObservableCollection<LogEntry> All { get; } = new();
    public ObservableCollection<LogEntry> Errors { get; } = new();

    public LogService()
    {
        Directory.CreateDirectory(ConfigStore.LogsDir);
        var day = DateTime.Now.ToString("yyyy-MM-dd");
        _allFile = Path.Combine(ConfigStore.LogsDir, $"hub-{day}.log");
        _errFile = Path.Combine(ConfigStore.LogsDir, $"errors-{day}.log");
    }

    public IReadOnlyList<LogEntry> Snapshot(string? source = null)
    {
        List<LogEntry> Copy()
        {
            lock (_gate)
            {
                IEnumerable<LogEntry> query = All;
                if (!string.IsNullOrWhiteSpace(source))
                    query = query.Where(e => e.Source.Equals(source, StringComparison.OrdinalIgnoreCase));
                return query.ToList();
            }
        }

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
            return Copy();
        return dispatcher.Invoke(Copy);
    }

    public void Info(string source, string message) => Add("INFO", source, message);
    public void Bypass(string source, string message) => Add("BYPASS", source, message);
    public void Error(string source, string message) => Add("ERROR", source, message);
    public void Sys(string message) => Add("SYS", "SYS", message);

    public void Clear()
    {
        RunOnUi(() =>
        {
            All.Clear();
            Errors.Clear();
        });
    }

    private void Add(string level, string source, string message)
    {
        var entry = new LogEntry
        {
            Time = DateTime.Now,
            Level = level,
            Source = source,
            Message = message
        };

        var line = entry.Display + Environment.NewLine;
        try
        {
            File.AppendAllText(_allFile, line);
            if (level == "ERROR")
                File.AppendAllText(_errFile, line);
        }
        catch
        {
            // ignored
        }

        RunOnUi(() =>
        {
            lock (_gate)
            {
                All.Add(entry);
                Trim(All);
                if (level == "ERROR")
                {
                    Errors.Add(entry);
                    Trim(Errors);
                }
            }
        });
    }

    private static void Trim(ObservableCollection<LogEntry> list)
    {
        while (list.Count > MaxUiLines)
            list.RemoveAt(0);
    }

    private static void RunOnUi(Action action)
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
            action();
        else
            dispatcher.BeginInvoke(action);
    }
}
