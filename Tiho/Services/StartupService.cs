using System.Diagnostics;
using System.Security.Principal;
using System.Xml.Linq;

namespace Tiho.Services;

public static class StartupService
{
    private static string TaskName => "Tiho-" + WindowsIdentity.GetCurrent().User!.Value;
    public static async Task SetEnabledAsync(bool enabled)
    {
        if (!enabled) { await RunAsync(new[] { "/Delete", "/TN", TaskName, "/F" }, ignoreFailure: true); return; }
        var ns = XNamespace.Get("http://schemas.microsoft.com/windows/2004/02/mit/task");
        var user = WindowsIdentity.GetCurrent().User!.Value;
        var path = Environment.ProcessPath ?? throw new InvalidOperationException("Не найден путь приложения.");
        var task = new XDocument(new XElement(ns + "Task", new XAttribute("version", "1.4"),
            new XElement(ns + "Triggers", new XElement(ns + "LogonTrigger", new XElement(ns + "Enabled", true), new XElement(ns + "UserId", user), new XElement(ns + "Delay", "PT10S"))),
            new XElement(ns + "Principals", new XElement(ns + "Principal", new XAttribute("id", "Author"), new XElement(ns + "UserId", user), new XElement(ns + "LogonType", "InteractiveToken"), new XElement(ns + "RunLevel", "HighestAvailable"))),
            new XElement(ns + "Settings", new XElement(ns + "MultipleInstancesPolicy", "IgnoreNew"), new XElement(ns + "DisallowStartIfOnBatteries", false), new XElement(ns + "StopIfGoingOnBatteries", false), new XElement(ns + "StartWhenAvailable", true), new XElement(ns + "ExecutionTimeLimit", "PT0S"), new XElement(ns + "RestartOnFailure", new XElement(ns + "Interval", "PT1M"), new XElement(ns + "Count", 3))),
            new XElement(ns + "Actions", new XAttribute("Context", "Author"), new XElement(ns + "Exec", new XElement(ns + "Command", path), new XElement(ns + "Arguments", "--background"), new XElement(ns + "WorkingDirectory", AppContext.BaseDirectory)))));
        var temp = Path.Combine(ConfigStore.RootDir, "startup-task.xml");
        try { task.Save(temp); await RunAsync(new[] { "/Create", "/TN", TaskName, "/XML", temp, "/F" }, false); }
        finally { File.Delete(temp); }
    }

    private static async Task RunAsync(IEnumerable<string> args, bool ignoreFailure)
    {
        var info = new ProcessStartInfo("schtasks.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Не удалось настроить автозапуск.");
        var error = process.StandardError.ReadToEndAsync();
        var output = process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync(); await output;
        if (process.ExitCode != 0 && !ignoreFailure) throw new InvalidOperationException("Не удалось настроить автозапуск: " + await error);
    }
}
