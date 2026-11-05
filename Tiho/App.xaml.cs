using System.Windows;

namespace Tiho;

public partial class App : System.Windows.Application
{
    private Mutex? _mutex;
    private bool _ownsMutex;
    private EventWaitHandle? _quit;
    private RegisteredWaitHandle? _quitWait;
    protected override void OnStartup(StartupEventArgs e)
    {
        var eventName = @"Local\Tiho.Quit." + System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
        if (e.Args.Contains("--quit"))
        {
            try { using var quit = EventWaitHandle.OpenExisting(eventName); quit.Set(); } catch (WaitHandleCannotBeOpenedException) { }
            Shutdown(); return;
        }
        _mutex = new Mutex(true, @"Local\Tiho.SingleInstance", out _ownsMutex);
        if (!_ownsMutex) { MessageBox.Show("Tiho уже работает. Откройте его через значок в трее.", "Tiho"); Shutdown(); return; }
        _quit = new EventWaitHandle(false, EventResetMode.AutoReset, eventName);
        _quitWait = ThreadPool.RegisterWaitForSingleObject(_quit, (_, _) => Dispatcher.BeginInvoke(() => (MainWindow as MainWindow)?.RequestExit()), null, Timeout.Infinite, false);
        DispatcherUnhandledException += (_, args) => { MessageBox.Show(args.Exception.Message, "Tiho", MessageBoxButton.OK, MessageBoxImage.Error); args.Handled = true; };
        TaskScheduler.UnobservedTaskException += (_, args) => args.SetObserved();
        base.OnStartup(e);
    }
    protected override void OnExit(ExitEventArgs e)
    {
        _quitWait?.Unregister(null); _quit?.Dispose();
        if (_ownsMutex) _mutex?.ReleaseMutex(); _mutex?.Dispose(); base.OnExit(e);
    }
}
