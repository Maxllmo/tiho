using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using ProxyHub.Models;
using ProxyHub.Services;
using WinForms = System.Windows.Forms;

namespace ProxyHub;

public partial class MainWindow : Window
{
    private readonly LogService _log = new();
    private readonly HubStats _stats = new();
    private readonly SystemProxyService _systemProxy = new();
    private readonly DispatcherTimer _statsTimer = new() { Interval = TimeSpan.FromMilliseconds(400) };
    private LocalHttpProxy? _proxy;
    private AppConfig _config = new();
    private WinForms.NotifyIcon? _tray;
    private System.Drawing.Icon? _appIcon;
    private bool _reallyExit;
    private bool _pcOn;
    private bool _suppressOptionEvents;
    private bool _trayHintShown;

    public MainWindow()
    {
        InitializeComponent();
        _proxy = new LocalHttpProxy(_log, _stats, () => _config);
        LstAll.ItemsSource = _log.All;
        LstErrors.ItemsSource = _log.Errors;
        _log.All.CollectionChanged += (_, _) => ScrollToEnd(LstAll);
        _log.Errors.CollectionChanged += (_, _) => ScrollToEnd(LstErrors);
        _statsTimer.Tick += (_, _) => RefreshStats();
        _statsTimer.Start();
        InitTray();
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        _config = ConfigStore.Load();
        _suppressOptionEvents = true;
        ApplyConfigToUi(_config);
        _suppressOptionEvents = false;
        RefreshLanLabels();
        RefreshStatus();
        _log.Sys("Proxy Hub запущен.");
        _log.Sys("Сайты .ru и .рф всегда идут напрямую, мимо Amnezia.");

        if (!_config.PcProxyEnabled && _systemProxy.IsPointingToUs(_config.ListenPort))
        {
            _systemProxy.Restore();
            _log.Sys("Восстановлены прежние настройки прокси Windows после прошлого запуска.");
        }

        if (_config.PcProxyEnabled)
            await SetPcProxyAsync(true);
        else
            await SyncHubAsync();
    }

    private async void Window_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_reallyExit && ChkTray.IsChecked == true)
        {
            e.Cancel = true;
            Hide();
            if (_tray is not null)
            {
                _tray.Visible = true;
                if (!_trayHintShown)
                {
                    _tray.ShowBalloonTip(2500, "Proxy Hub", "Работает в трее.", WinForms.ToolTipIcon.Info);
                    _trayHintShown = true;
                }
            }
            return;
        }

        SaveFromUi();
        await StopHubAsync(restorePc: true);
        if (_tray is not null)
        {
            _tray.Visible = false;
            _tray.Icon = null;
            _tray.Dispose();
            _tray = null;
        }
        _appIcon?.Dispose();
        _appIcon = null;
    }

    private void Window_StateChanged(object sender, EventArgs e)
    {
        if (WindowState == WindowState.Minimized && ChkTray.IsChecked == true)
        {
            Hide();
            WindowState = WindowState.Normal;
            if (_tray is not null)
                _tray.Visible = true;
        }
    }

    private void InitTray()
    {
        _appIcon = LoadAppIcon();
        _tray = new WinForms.NotifyIcon
        {
            Text = "Proxy Hub",
            Visible = true,
            Icon = _appIcon
        };
        _tray.DoubleClick += (_, _) => RestoreFromTray();
        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("Открыть", null, (_, _) => RestoreFromTray());
        menu.Items.Add("Выход", null, (_, _) =>
        {
            _reallyExit = true;
            Close();
        });
        _tray.ContextMenuStrip = menu;
    }

    private static System.Drawing.Icon LoadAppIcon()
    {
        try
        {
            var info = System.Windows.Application.GetResourceStream(new Uri("pack://application:,,,/Assets/app.ico"));
            if (info?.Stream is not null)
            {
                using (info.Stream)
                {
                    var size = WinForms.SystemInformation.SmallIconSize;
                    int w = Math.Max(16, size.Width);
                    int h = Math.Max(16, size.Height);
                    using var tmp = new System.Drawing.Icon(info.Stream, w, h);
                    return (System.Drawing.Icon)tmp.Clone();
                }
            }
        }
        catch
        {
            // fall through to exe icon
        }

        try
        {
            var path = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(path))
            {
                var extracted = System.Drawing.Icon.ExtractAssociatedIcon(path);
                if (extracted is not null)
                    return extracted;
            }
        }
        catch
        {
            // fall through to system icon
        }

        return (System.Drawing.Icon)System.Drawing.SystemIcons.Application.Clone();
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void ApplyConfigToUi(AppConfig cfg)
    {
        CmbType.SelectedIndex = cfg.UpstreamType.Equals("HTTP", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        TxtHost.Text = cfg.Host;
        TxtPort.Text = cfg.Port.ToString(CultureInfo.InvariantCulture);
        TxtUser.Text = cfg.Username;
        TxtPass.Password = cfg.Password;
        ChkAutoHub.IsChecked = cfg.AutoStartHub;
        ChkTray.IsChecked = cfg.MinimizeToTray;
        ChkStartup.IsChecked = cfg.StartWithWindows;
        RadPs5Hub.IsChecked = cfg.Ps5ViaLocalHub;
        RadPs5Direct.IsChecked = !cfg.Ps5ViaLocalHub;
    }

    private void SaveFromUi()
    {
        _config.UpstreamType = (CmbType.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "SOCKS5";
        _config.Host = TxtHost.Text.Trim();
        _config.Port = ParsePort(TxtPort.Text, 1080);
        _config.Username = TxtUser.Text.Trim();
        _config.Password = TxtPass.Password;
        if (_config.ListenPort is <= 0 or > 65535)
            _config.ListenPort = 3128;
        _config.AutoStartHub = ChkAutoHub.IsChecked == true;
        _config.MinimizeToTray = ChkTray.IsChecked == true;
        _config.StartWithWindows = ChkStartup.IsChecked == true;
        _config.Ps5ViaLocalHub = RadPs5Hub.IsChecked == true;
        _config.PcProxyEnabled = _pcOn;
        ConfigStore.Save(_config);
        StartupService.SetEnabled(_config.StartWithWindows);
        RefreshStatus();
        RefreshLanLabels();
    }

    private static void ScrollToEnd(ListBox list)
    {
        if (list.Items.Count == 0)
            return;
        list.ScrollIntoView(list.Items[^1]);
    }

    private static int ParsePort(string text, int fallback)
        => int.TryParse(text.Trim(), out var p) && p is > 0 and <= 65535 ? p : fallback;

    private async void BtnApply_Click(object sender, RoutedEventArgs e)
    {
        SaveFromUi();
        _log.Sys($"Настройки применены: {_config.UpstreamType} {_config.Host}:{_config.Port}");
        await SyncHubAsync();
        LblTest.Text = "Сохранено.";
    }

    private async void BtnTest_Click(object sender, RoutedEventArgs e)
    {
        SaveFromUi();
        LblTest.Text = "Проверяю upstream...";
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(12));
            var ip = await ProxyTester.TestAsync(_config, cts.Token);
            LblTest.Text = $"Работает. Исходящий IP: {ip}";
            _log.Sys($"Проверка upstream успешна. Исходящий IP {ip}");
            RefreshStatus(testedOk: true);
        }
        catch (Exception ex)
        {
            LblTest.Text = $"Ошибка: {ex.Message}";
            _log.Error("SYS", $"Проверка upstream: {ex.Message}");
            RefreshStatus(testedOk: false);
        }
    }

    private async void BtnPc_Click(object sender, RoutedEventArgs e)
    {
        await SetPcProxyAsync(!_pcOn);
    }

    private bool HubNeeded =>
        _config.AutoStartHub || _pcOn || _config.Ps5ViaLocalHub;

    private async Task SyncHubAsync()
    {
        if (HubNeeded)
            await StartHubAsync();
        else if (_proxy?.IsRunning == true)
            await StopHubAsync(restorePc: false);
    }

    private async Task StartHubAsync()
    {
        if (_proxy?.IsRunning == true)
            return;

        SaveFromUi();
        try
        {
            _proxy ??= new LocalHttpProxy(_log, _stats, () => _config);
            await _proxy.StartAsync(_config.ListenPort);
            RefreshLanLabels();
            RefreshStatus();
            if (!_config.IsConfigured)
                _log.Sys("Хаб слушает, но upstream ещё не задан. Запросы не на .ru/.рф получат 502.");
        }
        catch (Exception ex)
        {
            _log.Error("SYS", $"Не удалось запустить хаб: {ex.Message}");
            MessageBox.Show(ex.Message, "Proxy Hub", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task StopHubAsync(bool restorePc)
    {
        if (restorePc && _pcOn)
            await SetPcProxyAsync(false);

        if (_proxy is not null)
            await _proxy.StopAsync();

        RefreshStatus();
        RefreshLanLabels();
    }

    private async Task SetPcProxyAsync(bool enable)
    {
        SaveFromUi();
        if (enable)
        {
            if (_proxy?.IsRunning != true)
                await StartHubAsync();
            if (_proxy?.IsRunning != true)
                return;

            _systemProxy.EnableLocal(_proxy.BoundPort);
            _pcOn = true;
            _config.PcProxyEnabled = true;
            ConfigStore.Save(_config);
            BtnPc.Content = "Отключить на этом ПК";
            BtnPc.Style = (Style)FindResource("DangerBtn");
            _log.Sys($"Прокси включён на этом ПК → 127.0.0.1:{_proxy.BoundPort}. Трафик ПК пишется в лог с меткой PC.");
        }
        else
        {
            _systemProxy.Restore();
            _systemProxy.ForgetSnapshot();
            _pcOn = false;
            _config.PcProxyEnabled = false;
            ConfigStore.Save(_config);
            BtnPc.Content = "Включить на этом ПК";
            BtnPc.Style = (Style)FindResource("PrimaryBtn");
            _log.Sys("Прокси на этом ПК выключен.");
        }
        RefreshStatus();
        await SyncHubAsync();
    }

    private async void ChkOptions_Changed(object sender, RoutedEventArgs e)
    {
        if (_suppressOptionEvents || !IsLoaded)
            return;
        SaveFromUi();
        await SyncHubAsync();
    }

    private void BtnClearLogs_Click(object sender, RoutedEventArgs e) => _log.Clear();

    private void BtnOpenLogs_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(ConfigStore.LogsDir);
        Process.Start(new ProcessStartInfo
        {
            FileName = ConfigStore.LogsDir,
            UseShellExecute = true
        });
    }

    private void BtnCopyPs5_Click(object sender, RoutedEventArgs e)
    {
        var text = GetPs5Endpoint();
        if (string.IsNullOrEmpty(text))
        {
            LblTest.Text = "Сначала укажите сервер Squid сверху.";
            return;
        }
        Clipboard.SetText(text);
        LblTest.Text = $"Скопировано: {text}";
        _log.Sys($"Адрес для PS5 скопирован: {text}");
    }

    private void RefreshLanLabels()
    {
        var listen = ListenPortNow();
        if (RadPs5Hub.IsChecked == true)
        {
            LblPs5.Text = $"Адрес: {LanInfo.PrimaryIpv4()}\nПорт:  {listen}";
        }
        else if (_config.IsConfigured)
        {
            LblPs5.Text = $"Адрес: {_config.Host}\nПорт:  {_config.Port}";
        }
        else
        {
            LblPs5.Text = "Адрес: —\nПорт:  —";
        }
    }

    private int ListenPortNow()
    {
        if (_proxy?.IsRunning == true)
            return _proxy.BoundPort;
        return _config.ListenPort is > 0 and <= 65535 ? _config.ListenPort : 3128;
    }

    private string GetPs5Endpoint()
    {
        if (RadPs5Hub.IsChecked == true)
            return $"{LanInfo.PrimaryIpv4()}:{ListenPortNow()}";

        if (!_config.IsConfigured)
            return "";
        return $"{_config.Host}:{_config.Port}";
    }

    private void RefreshStatus(bool? testedOk = null)
    {
        var hubOn = _proxy?.IsRunning == true;
        DotHub.Fill = BrushOf(hubOn ? "#3ECF8E" : "#F0617D");
        LblHub.Text = hubOn ? $"Хаб :{_proxy!.BoundPort}" : "Хаб выключен";

        DotPc.Fill = BrushOf(_pcOn ? "#3ECF8E" : "#8A9BB5");
        LblPc.Text = _pcOn ? "ПК через хаб" : "ПК напрямую";

        if (testedOk == true)
        {
            DotUp.Fill = BrushOf("#3ECF8E");
            LblUp.Text = "Upstream OK";
        }
        else if (testedOk == false)
        {
            DotUp.Fill = BrushOf("#F0617D");
            LblUp.Text = "Upstream ошибка";
        }
        else if (_config.IsConfigured)
        {
            DotUp.Fill = BrushOf("#F0B429");
            LblUp.Text = $"{_config.UpstreamType} {_config.Host}:{_config.Port}";
        }
        else
        {
            DotUp.Fill = BrushOf("#F0B429");
            LblUp.Text = "Прокси не задан";
        }
    }

    private void RefreshStats()
    {
        LblStats.Text =
            $"запросы {Interlocked.Read(ref _stats.Requests)}   активных {Volatile.Read(ref _stats.Active)}   ошибки {Interlocked.Read(ref _stats.Errors)}   ↑ {FormatBytes(Interlocked.Read(ref _stats.BytesUp))}   ↓ {FormatBytes(Interlocked.Read(ref _stats.BytesDown))}";
        LblLastError.Text = string.IsNullOrEmpty(_stats.LastError) ? "" : _stats.LastError;
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:0.0} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / 1024.0 / 1024.0:0.0} MB";
        return $"{bytes / 1024.0 / 1024.0 / 1024.0:0.00} GB";
    }

    private static SolidColorBrush BrushOf(string hex)
        => new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(hex));
}

public sealed class LogLevelBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return (value as string) switch
        {
            "ERROR" => new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#F0617D")!),
            "BYPASS" => new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#F0B429")!),
            "SYS" => new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#4BA3F5")!),
            _ => new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#D5DEEB")!)
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
