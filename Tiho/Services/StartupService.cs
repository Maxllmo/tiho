using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Tiho.Services;

public static class StartupService
{
    // Register a definition through COM. No XML-file encoding or console code pages are involved.
    public static Task SetEnabledAsync(bool enabled) => Task.Run(() => Configure(enabled));

    private static void Configure(bool enabled)
    {
        var objects = new List<object>();
        object Keep(object value) { objects.Add(value); return value; }
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new InvalidOperationException("Планировщик заданий Windows недоступен.");
            dynamic service = Keep(Activator.CreateInstance(type)!);
            service.Connect();
            dynamic folder = Keep(service.GetFolder(@"\"));
            var user = WindowsIdentity.GetCurrent().User?.Value ?? throw new InvalidOperationException("Не удалось определить учётную запись Windows.");
            var name = "Tiho-" + user;
            if (!enabled)
            {
                try { folder.DeleteTask(name, 0); }
                catch (COMException ex) when (ex.HResult == unchecked((int)0x80070002)) { }
                return;
            }

            dynamic definition = Keep(service.NewTask(0));
            dynamic registration = Keep(definition.RegistrationInfo);
            registration.Description = "Запуск Tiho при входе пользователя в Windows.";
            dynamic principal = Keep(definition.Principal);
            principal.UserId = user;
            principal.LogonType = 3; // TASK_LOGON_INTERACTIVE_TOKEN.
            principal.RunLevel = 1; // TASK_RUNLEVEL_HIGHEST, required for TUN.
            dynamic settings = Keep(definition.Settings);
            settings.Enabled = true;
            settings.MultipleInstances = 2; // TASK_INSTANCES_IGNORE_NEW.
            settings.DisallowStartIfOnBatteries = false;
            settings.StopIfGoingOnBatteries = false;
            settings.StartWhenAvailable = true;
            settings.ExecutionTimeLimit = "PT0S";
            settings.RestartInterval = "PT1M";
            settings.RestartCount = 3;
            dynamic triggers = Keep(definition.Triggers);
            dynamic trigger = Keep(triggers.Create(9)); // TASK_TRIGGER_LOGON.
            trigger.UserId = user;
            trigger.Enabled = true;
            trigger.Delay = "PT10S";
            dynamic actions = Keep(definition.Actions);
            dynamic action = Keep(actions.Create(0)); // TASK_ACTION_EXEC.
            action.Path = Environment.ProcessPath ?? throw new InvalidOperationException("Не найден путь Tiho.");
            action.Arguments = "--background";
            action.WorkingDirectory = AppContext.BaseDirectory;
            Keep(folder.RegisterTaskDefinition(name, definition, 6, user, null, 3, null));
        }
        finally
        {
            for (var i = objects.Count - 1; i >= 0; i--)
                if (Marshal.IsComObject(objects[i])) Marshal.FinalReleaseComObject(objects[i]);
        }
    }
}
