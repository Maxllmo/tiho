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
    private readonly ClientTracker _clients = new();
    private readonly SystemProxyService _systemProxy = new();
    private readonly SingBoxService _vpn = new();
    private readonly DispatcherTimer _statsTimer = new() { Interval = TimeSpan.FromMilliseconds(400) };
    private LocalHttpProxy? _proxy;
    private AppConfig _config = new();
    private WinForms.NotifyIcon? _tray;
    private System.Drawing.Icon? _appIcon;
    private bool _reallyExit;
    private bool _pcOn;
    private bool _suppressOptionEvents;
    private bool _trayHintShown;
    private string? _editingId;

    public MainWindow()
    {
        InitializeComponent();
        _proxy = new LocalHttpProxy(_log, _stats, _clients, () => _config);
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
        ApplyOptionsToUi(_config);
        _editingId = string.IsNullOrEmpty(_config.ActiveProfileId)
            ? _config.Profiles.FirstOrDefault()?.Id
            : _config.ActiveProfileId;
        LoadEditor();
        _suppressOptionEvents = false;
        SyncLiveUpstream();
        RefreshStatus();
        _log.Sys("Proxy Hub запущен.");
        _log.Sys("Сайты .ru и .рф всегда идут напрямую, мимо прокси и VPN.");
        if (_config.Profiles.Count > 0)
            _log.Sys($"Загружено серверов: {_config.Profiles.Count}.");

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

        PersistEditor();
        SaveConfig();
        await StopHubAsync(restorePc: true);
        await _vpn.StopAsync();
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

    private void ApplyOptionsToUi(AppConfig cfg)
    {
        ChkAutoHub.IsChecked = cfg.AutoStartHub;
        ChkTray.IsChecked = cfg.MinimizeToTray;
        ChkStartup.IsChecked = cfg.StartWithWindows;
    }

    private ServerProfile? SelectedProfile =>
        _config.Profiles.FirstOrDefault(p => p.Id == _editingId)
        ?? _config.ActiveProfile
        ?? _config.Profiles.FirstOrDefault();

    private void PersistEditor()
    {
        var profile = EnsureAmnezia();
        profile.Name = "Amnezia";
        profile.Kind = "proxy";
        profile.Protocol = "HTTP";
        profile.Host = TxtHost.Text.Trim();
        profile.Port = ParsePort(TxtPort.Text, profile.Port > 0 ? profile.Port : 3128);
        profile.Username = TxtUser.Text.Trim();
        profile.Password = TxtPass.Password;
        _editingId = profile.Id;
        _config.ActiveProfileId = profile.Id;
    }

    private ServerProfile EnsureAmnezia()
    {
        var profile = _config.Profiles.FirstOrDefault(p => p.Id == _editingId && !p.IsVpn)
                      ?? _config.Profiles.FirstOrDefault(p => !p.IsVpn);
        if (profile is not null)
            return profile;

        profile = new ServerProfile
        {
            Name = "Amnezia",
            Kind = "proxy",
            Protocol = "HTTP",
            Port = 3128
        };
        _config.Profiles.Add(profile);
        return profile;
    }

    private void LoadEditor()
    {
        var profile = _config.Profiles.FirstOrDefault(p => p.Id == _editingId && !p.IsVpn)
                      ?? _config.Profiles.FirstOrDefault(p => !p.IsVpn);
        _editingId = profile?.Id;
        TxtHost.Text = profile?.Host ?? "";
        TxtPort.Text = (profile?.Port is > 0 and <= 65535 ? profile.Port : 3128).ToString(CultureInfo.InvariantCulture);
        TxtUser.Text = profile?.Username ?? "";
        TxtPass.Password = profile?.Password ?? "";
    }

    private void SaveConfig()
    {
        if (_config.ListenPort is <= 0 or > 65535)
            _config.ListenPort = 3128;
        _config.AutoStartHub = ChkAutoHub.IsChecked == true;
        _config.MinimizeToTray = ChkTray.IsChecked == true;
        _config.StartWithWindows = ChkStartup.IsChecked == true;
        _config.PcProxyEnabled = _pcOn;
        SyncLiveUpstream();
        ConfigStore.Save(_config);
        StartupService.SetEnabled(_config.StartWithWindows);
        RefreshStatus();
        UpdateTrayTip();
    }

    private void SyncLiveUpstream()
        => _config.SyncLiveFromActive(_vpn.IsRunning ? _vpn.SocksPort : null);

    private async Task SyncActiveCoreAsync()
    {
        var profile = _config.ActiveProfile;
        if (profile is { IsVpn: true, IsConfigured: true })
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(4));
            await _vpn.StartAsync(profile, _log, cts.Token);
        }
        else if (_vpn.IsRunning)
        {
            await _vpn.StopAsync();
            _log.Sys("VPN-ядро остановлено.");
        }

        SyncLiveUpstream();
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
        PersistEditor();
        SaveConfig();
        var profile = SelectedProfile;
        _log.Sys(profile is null
            ? "Настройки сохранены."
            : $"Сохранён сервер: {profile.Name}");
        if (profile is not null && profile.Id == _config.ActiveProfileId)
        {
            await SyncActiveCoreAsync();
            await SyncHubAsync();
        }
        LblTest.Text = "Сохранено.";
        LoadEditor();
    }

    private async void BtnTest_Click(object sender, RoutedEventArgs e)
    {
        PersistEditor();
        var profile = SelectedProfile;
        if (profile is not null)
            _config.ActiveProfileId = profile.Id;

        LblTest.Text = "Проверяю исходящий IP...";
        try
        {
            await SyncActiveCoreAsync();
            SaveConfig();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var ip = await ProxyTester.TestAsync(_config, cts.Token);
            LblTest.Text = $"Работает. Исходящий IP: {ip}";
            _log.Sys($"Проверка успешна. Исходящий IP {ip}");
            RefreshStatus(testedOk: true);
        }
        catch (Exception ex)
        {
            LblTest.Text = $"Ошибка: {ex.Message}";
            _log.Error("SYS", $"Проверка: {ex.Message}");
            RefreshStatus(testedOk: false);
        }
    }

    private async void BtnPc_Click(object sender, RoutedEventArgs e)
    {
        await SetPcProxyAsync(!_pcOn);
    }

    private bool HubNeeded =>
        _config.AutoStartHub || _pcOn || _config.Ps5ViaLocalHub || (_config.ActiveProfile?.IsVpn == true);

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

        PersistEditor();
        SaveConfig();
        try
        {
            _proxy ??= new LocalHttpProxy(_log, _stats, _clients, () => _config);
            await _proxy.StartAsync(_config.ListenPort);
            RefreshStatus();
            if (!_config.IsConfigured)
                _log.Sys("Хаб слушает, но активный сервер ещё не задан. Запросы не на .ru/.рф получат 502.");
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
    }

    private async Task SetPcProxyAsync(bool enable)
    {
        PersistEditor();
        SaveConfig();
        if (enable)
        {
            if (_config.ActiveProfile is { IsVpn: true })
                await SyncActiveCoreAsync();
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
        PersistEditor();
        SaveConfig();
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

    private void RefreshStatus(bool? testedOk = null)
    {
        var hubOn = _proxy?.IsRunning == true;
        DotHub.Fill = BrushOf(hubOn ? "#3ECF8E" : "#F0617D");
        LblHub.Text = hubOn ? $"Хаб :{_proxy!.BoundPort}" : "Хаб выключен";

        DotPc.Fill = BrushOf(_pcOn ? "#3ECF8E" : "#8A9BB5");
        LblPc.Text = _pcOn ? "ПК через хаб" : "ПК напрямую";

        var active = _config.ActiveProfile;
        if (testedOk == true)
        {
            DotUp.Fill = BrushOf("#3ECF8E");
            LblUp.Text = active is null ? "Upstream OK" : active.Name;
        }
        else if (testedOk == false)
        {
            DotUp.Fill = BrushOf("#F0617D");
            LblUp.Text = "Ошибка сервера";
        }
        else if (active is { IsVpn: true } && _vpn.IsRunning)
        {
            DotUp.Fill = BrushOf("#3ECF8E");
            LblUp.Text = $"VPN {active.Name}";
        }
        else if (active is { IsConfigured: true, IsVpn: false })
        {
            DotUp.Fill = BrushOf("#F0B429");
            LblUp.Text = $"{active.Protocol} {active.Host}:{active.Port}";
        }
        else if (active is { IsVpn: true })
        {
            DotUp.Fill = BrushOf("#F0B429");
            LblUp.Text = $"VPN не подключён";
        }
        else
        {
            DotUp.Fill = BrushOf("#F0B429");
            LblUp.Text = "Сервер не задан";
        }

        UpdateTrayTip();
    }

    private void UpdateTrayTip()
    {
        if (_tray is null)
            return;
        var name = _config.ActiveProfile?.Name ?? "сервер не задан";
        var text = $"Proxy Hub — {name}";
        _tray.Text = text.Length <= 63 ? text : text[..63];
    }

    private void RefreshStats()
    {
        LblStats.Text =
            $"запросы {Interlocked.Read(ref _stats.Requests)}   активных {Volatile.Read(ref _stats.Active)}   ошибки {Interlocked.Read(ref _stats.Errors)}   ↑ {HubStats.FormatBytes(Interlocked.Read(ref _stats.BytesUp))}   ↓ {HubStats.FormatBytes(Interlocked.Read(ref _stats.BytesDown))}";
        LblLastError.Text = string.IsNullOrEmpty(_stats.LastError) ? "" : _stats.LastError;
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
