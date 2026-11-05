using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using Tiho.Models;
using Tiho.Services;
using WinForms = System.Windows.Forms;

namespace Tiho;

public partial class MainWindow : Window
{
    private readonly LogService _log = new();
    private readonly TunnelService _tunnel = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly ObservableCollection<string> _excludedApps = new();
    private readonly Queue<double> _speeds = new();
    private AppConfig _config = new();
    private UsageTracker? _usage;
    private WinForms.NotifyIcon? _tray;
    private System.Drawing.Icon? _icon;
    private CancellationTokenSource? _connecting;
    private bool _loaded, _desired, _sessionStarted, _transitioning, _polling, _pingBusy, _allowClose, _closing, _healthChecked, _windowClosed;
    private int _failures, _apiFailures, _tick, _connectionEpoch;
    private int? _delay;
    private DateTime _retryAt;

    public MainWindow()
    {
        InitializeComponent();
        LstExcludedApps.ItemsSource = _excludedApps;
        LstLogs.ItemsSource = _log.All;
        _timer.Tick += async (_, _) => await PollAsync();
        InitTray();
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        WindowTheme.ApplyDarkCaption(this);
    }

    private void Navigation_Click(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string page } && int.TryParse(page, out var index)) Tabs.SelectedIndex = index;
    }

    private void Tabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.OriginalSource != Tabs || LblPageTitle is null) return;
        LblPageTitle.Text = Tabs.SelectedIndex switch { 1 => "Настройки", 2 => "Логи", _ => "Подключение" };
        NavConnection.IsChecked = Tabs.SelectedIndex == 0;
        NavSettings.IsChecked = Tabs.SelectedIndex == 1;
        NavLogs.IsChecked = Tabs.SelectedIndex == 2;
    }

    private void BtnConfigHelp_Click(object sender, RoutedEventArgs e)
        => System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://github.com/Maxllmo/ProxyHub/blob/main/docs/amnezia-config.md") { UseShellExecute = true });

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            Height = Math.Min(Height, SystemParameters.WorkArea.Height);
            Width = Math.Min(Width, SystemParameters.WorkArea.Width);
            _config = ConfigStore.Load();
            _usage = new UsageTracker(Path.Combine(ConfigStore.RootDir, "usage.json"));
            RoutingRules.EnsureBundled();
            ChkAutoConnect.IsChecked = _config.AutoConnect; ChkStartup.IsChecked = _config.StartWithWindows;
            ChkTray.IsChecked = _config.MinimizeToTray; ChkRussia.IsChecked = _config.BypassRussia;
            TxtDomains.Text = string.Join(Environment.NewLine, _config.DirectDomains);
            foreach (var app in _config.ExcludedApps) _excludedApps.Add(app);
            ReloadServers();
            _loaded = true;
            _log.Sys("Tiho запущен. Логи доступны только до закрытия приложения.");
            NetworkChange.NetworkAvailabilityChanged += NetworkAvailabilityChanged;
            _timer.Start(); RefreshUi();
            await TryStartupAsync();
            if (_closing) return;
            if (Environment.GetCommandLineArgs().Contains("--background") && _config.Profiles.Count > 0) Hide();
            if (_config.AutoConnect && _config.ActiveProfile is not null) { _desired = true; await ConnectAsync(); }
        }
        catch (Exception ex) { _log.Error("Tiho", ex.Message); ShowNotice("Не удалось загрузить Tiho: " + ex.Message); BtnConnect.IsEnabled = false; BtnSave.IsEnabled = false; }
    }

    private async Task TryStartupAsync()
    {
        try { await StartupService.SetEnabledAsync(_config.StartWithWindows); }
        catch (Exception ex) { _log.Error("Tiho", "Автозапуск: " + ex.Message); ShowNotice("Автозапуск не настроен. Подробности — на вкладке «Логи». VPN можно включить вручную."); }
    }

    private async void BtnConnect_Click(object sender, RoutedEventArgs e)
    {
        if (_desired) await RunUiAsync(DisconnectAsync);
        else
        {
            if (_config.ActiveProfile is null) { Tabs.SelectedIndex = 1; LblSettingsResult.Text = "Сначала импортируйте клиентский .conf AmneziaWG или добавьте прокси."; return; }
            _desired = true; _failures = 0; await RunUiAsync(() => ConnectAsync());
        }
    }

    private async Task ConnectAsync()
    {
        if (_closing || !_desired || _transitioning) return;
        await _gate.WaitAsync(_lifetime.Token);
        if (_closing || !_desired || _tunnel.IsRunning) { _gate.Release(); return; }
        _transitioning = true;
        _connecting = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        _connecting.CancelAfter(TimeSpan.FromSeconds(45));
        LblStatus.Text = "Подключение…"; BtnConnect.Content = "Отменить"; StatusDot.Fill = Brush("#F0BD6D");
        try
        {
            await _tunnel.StartAsync(_config, _log, _connecting.Token);
            if (!_desired) { await _tunnel.StopAsync(); return; }
            if (!_sessionStarted) { _usage!.Begin(); _sessionStarted = true; } else _usage!.CoreRestarted();
            _connectionEpoch++; _failures = _apiFailures = 0; _delay = null; _healthChecked = false; _tick = 0;
            Notice.Visibility = Visibility.Collapsed;
            if (_config.ActiveProfile?.Protocol == "HTTP") ShowNotice("HTTP-прокси передаёт только TCP. UDP заблокирован. Для игр импортируйте AmneziaWG .conf.");
            _ = UpdatePingAsync();
        }
        catch (Exception ex)
        {
            _usage?.Pause();
            if (_desired && !_closing)
            {
                _log.Error("Tiho", ex is OperationCanceledException ? "Истекло время подключения." : ex.Message);
                ShowNotice(ex is OperationCanceledException ? "Сервер не подключился. Проверьте сеть и конфигурацию." : ex.Message);
                ScheduleRetry();
            }
        }
        finally { _connecting.Dispose(); _connecting = null; _transitioning = false; _gate.Release(); RefreshUi(); }
    }

    private void ScheduleRetry()
    {
        _failures++; _retryAt = DateTime.UtcNow.AddSeconds(Math.Min(30, Math.Pow(2, Math.Min(_failures, 5))));
        if (!_config.AutoConnect) _desired = false;
    }

    private async Task DisconnectAsync()
    {
        _desired = false; _connecting?.Cancel();
        await _gate.WaitAsync();
        _transitioning = true;
        try
        {
            if (_tunnel.IsRunning && _usage is not null)
                try { var counters = await _tunnel.GetCountersAsync(CancellationToken.None); _usage.Sample(counters.Upload, counters.Download); } catch { }
            await _tunnel.StopAsync(); _usage?.End(); _sessionStarted = false; _delay = null; _connectionEpoch++;
            _log.Sys("Отключено. Обычное подключение Windows восстановлено.");
        }
        finally { _transitioning = false; _gate.Release(); RefreshUi(); }
    }

    private async Task RestartAsync()
    {
        if (!_desired) return;
        _connecting?.Cancel();
        await _gate.WaitAsync();
        _transitioning = true;
        try
        {
            if (_tunnel.IsRunning && _usage is not null)
                try { var c = await _tunnel.GetCountersAsync(_lifetime.Token); _usage.Sample(c.Upload, c.Download); } catch { }
            _usage?.Pause(); await _tunnel.StopAsync();
        }
        finally { _transitioning = false; _gate.Release(); }
        await ConnectAsync();
    }

    private async Task PollAsync()
    {
        if (!_loaded || _closing || _polling || _transitioning) return;
        _polling = true;
        var epoch = _connectionEpoch;
        try
        {
            if (_tunnel.IsRunning)
            {
                var c = await _tunnel.GetCountersAsync(_lifetime.Token);
                if (epoch != _connectionEpoch || _transitioning || !_desired || _closing) return;
                _usage!.Sample(c.Upload, c.Download); _apiFailures = 0;
                LblConnections.Text = $"Соединений: {c.Connections}";
                _speeds.Enqueue(_usage.DownloadSpeed * 8 / 1_000_000); while (_speeds.Count > 60) _speeds.Dequeue();
                DrawChart();
                if (++_tick % 10 == 0) _usage.Save();
                if (_tick % 15 == 0) _ = UpdatePingAsync();
            }
            else if (_desired)
            {
                _usage?.Pause();
                if (DateTime.UtcNow >= _retryAt) await ConnectAsync();
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (epoch == _connectionEpoch && !_transitioning && ++_apiFailures >= 3 && _desired)
            {
                await _gate.WaitAsync();
                try
                {
                    if (epoch == _connectionEpoch && _desired)
                    {
                        _transitioning = true; _log.Error("Tiho", "Потеряна связь с VPN-ядром: " + ex.Message);
                        _usage?.Pause(); await _tunnel.StopAsync(); ScheduleRetry();
                    }
                }
                finally { _transitioning = false; _gate.Release(); }
            }
        }
        finally { _polling = false; if (!_closing) RefreshUi(); }
    }

    private async Task UpdatePingAsync()
    {
        if (_pingBusy || !_tunnel.IsRunning) return;
        _pingBusy = true; var epoch = _connectionEpoch;
        try
        {
            var delay = await _tunnel.MeasureDelayAsync(_lifetime.Token);
            if (epoch != _connectionEpoch || _closing) return;
            _delay = delay; _healthChecked = true;
            if (delay is null) { ShowNotice("Туннель включён, но сервер не прошёл проверку связи. Проверьте конфигурацию; следующая проверка автоматически."); _log.Error("Tiho", "Проверка HTTPS через сервер: нет ответа."); }
            else if (_config.ActiveProfile?.Protocol != "HTTP") Notice.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or ObjectDisposedException)
        { if (epoch == _connectionEpoch && !_closing) { _delay = null; _healthChecked = true; ShowNotice("Сервер не ответил на проверку связи. Повторная проверка автоматически."); } }
        finally { _pingBusy = false; if (!_closing) RefreshUi(); }
    }

    private async void BtnSave_Click(object sender, RoutedEventArgs e) => await RunUiAsync(async () =>
    {
        var domains = TxtDomains.Text.Split(new[] { '\r', '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries).Select(TunnelConfig.NormalizeDomain).Where(s => s.Length > 0).Distinct().ToList();
        _config.DirectDomains = domains; _config.ExcludedApps = _excludedApps.ToList();
        _config.AutoConnect = ChkAutoConnect.IsChecked == true; _config.StartWithWindows = ChkStartup.IsChecked == true;
        _config.MinimizeToTray = ChkTray.IsChecked == true; _config.BypassRussia = ChkRussia.IsChecked == true;
        ConfigStore.Save(_config); await TryStartupAsync();
        if (_desired) await RestartAsync();
        LblSettingsResult.Text = "Настройки применены."; _log.Sys("Настройки маршрутизации обновлены."); RefreshUi();
    });

    private async void BtnImport_Click(object sender, RoutedEventArgs e) => await RunUiAsync(async () =>
    {
        var dialog = new OpenFileDialog { Title = "Клиентская конфигурация AmneziaWG", Filter = "Конфигурация AmneziaWG (*.conf)|*.conf", Multiselect = false };
        if (dialog.ShowDialog(this) != true) return;
        var profile = AmneziaConfigImporter.Parse(await File.ReadAllTextAsync(dialog.FileName), Path.GetFileNameWithoutExtension(dialog.FileName));
        _config.Profiles.Add(profile);
        if (!_desired) _config.ActiveProfileId = profile.Id;
        ConfigStore.Save(_config); ReloadServers();
        LblSettingsResult.Text = _desired ? "Конфигурация добавлена. Выберите сервер в списке, чтобы переключиться." : "Конфигурация добавлена. Нажмите «Подключить» на главном экране.";
        if (!_desired) Tabs.SelectedIndex = 0;
    });

    private async void BtnAddProxy_Click(object sender, RoutedEventArgs e) => await RunUiAsync(async () =>
    {
        var dialog = new AddServerWindow { Owner = this };
        if (dialog.ShowDialog() != true || dialog.Result is null) return;
        _config.Profiles.Add(dialog.Result); _config.ActiveProfileId = dialog.Result.Id;
        ConfigStore.Save(_config); ReloadServers(); if (_desired) await RestartAsync();
        LblSettingsResult.Text = "Прокси добавлен.";
    });

    private async void BtnEditServer_Click(object sender, RoutedEventArgs e) => await RunUiAsync(async () =>
    {
        var profile = _config.ActiveProfile; if (profile is null) return;
        if (profile.IsAmnezia) { LblSettingsResult.Text = "Для изменения AmneziaWG импортируйте обновлённый .conf и удалите старый профиль."; return; }
        var dialog = new AddServerWindow(profile) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.Result is null) return;
        _config.Profiles[_config.Profiles.IndexOf(profile)] = dialog.Result;
        ConfigStore.Save(_config); ReloadServers(); if (_desired) await RestartAsync();
    });

    private async void BtnRemoveServer_Click(object sender, RoutedEventArgs e) => await RunUiAsync(async () =>
    {
        var profile = _config.ActiveProfile; if (profile is null) return;
        if (_desired) await DisconnectAsync();
        _config.Profiles.Remove(profile); _config.ActiveProfileId = _config.Profiles.FirstOrDefault()?.Id ?? "";
        ConfigStore.Save(_config); ReloadServers(); RefreshUi();
    });

    private async void CmbServers_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_loaded || CmbServers.SelectedItem is not ServerProfile selected || selected.Id == _config.ActiveProfileId) return;
        await RunUiAsync(async () => { _config.ActiveProfileId = selected.Id; ConfigStore.Save(_config); if (_desired) await RestartAsync(); RefreshUi(); });
    }

    private void ReloadServers()
    {
        var loaded = _loaded; _loaded = false; CmbServers.ItemsSource = null; CmbServers.ItemsSource = _config.Profiles;
        CmbServers.SelectedItem = _config.ActiveProfile; _loaded = loaded; RefreshUi();
    }
    private void BtnAddApp_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Программы, которые будут работать без VPN", Filter = "Программы Windows (*.exe)|*.exe", Multiselect = true };
        if (dialog.ShowDialog(this) == true) foreach (var file in dialog.FileNames) if (!_excludedApps.Contains(file, StringComparer.OrdinalIgnoreCase)) _excludedApps.Add(file);
    }
    private void BtnRemoveApp_Click(object sender, RoutedEventArgs e) { if (LstExcludedApps.SelectedItem is string path) _excludedApps.Remove(path); }
    private async void BtnUpdateRules_Click(object sender, RoutedEventArgs e)
    {
        BtnUpdateRules.IsEnabled = false;
        try { await RoutingRules.UpdateAsync(_lifetime.Token); LblRules.Text = "Обновлено " + DateTime.Now.ToString("dd.MM.yyyy HH:mm"); _log.Sys("Списки российских доменов и IP обновлены."); if (_desired) await RestartAsync(); }
        catch (Exception ex) { LblRules.Text = "Обновление не удалось; текущие списки сохранены."; _log.Error("Tiho", ex.Message); }
        finally { BtnUpdateRules.IsEnabled = true; }
    }

    private void BtnClearLogs_Click(object sender, RoutedEventArgs e) => _log.Clear();
    private void LogFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (LstLogs is null) return;
        CollectionViewSource.GetDefaultView(_log.All).Filter = ChkErrors.IsChecked == true ? item => item is LogEntry { Level: "ERROR" } : null;
    }

    private void RefreshUi()
    {
        var on = _tunnel.IsRunning; var profile = _config.ActiveProfile;
        if (!_transitioning)
        {
            var noResponse = on && _healthChecked && _delay is null;
            LblStatus.Text = noResponse ? "Сервер не отвечает" : on ? "Подключено" : _desired ? "Переподключение…" : "Отключено";
            StatusDot.Fill = Brush(noResponse ? "#F0BD6D" : on ? "#70DEB5" : _desired ? "#F0BD6D" : "#788396");
            BtnConnect.Content = _desired ? "Отключить" : "Подключить";
        }
        BtnConnect.Background = (System.Windows.Media.Brush)FindResource(_desired ? "RaisedBrush" : "AccentBrush");
        BtnConnect.Foreground = (System.Windows.Media.Brush)FindResource(_desired ? "TextBrush" : "InkBrush");
        BtnConnect.BorderBrush = (System.Windows.Media.Brush)FindResource(_desired ? "LineBrush" : "AccentBrush");
        LblServer.Text = profile is null ? "Добавьте сервер, чтобы начать" : $"{profile.Name} · {profile.Protocol}";
        LblRussiaBadge.Text = _config.BypassRussia ? "Россия напрямую" : "Россия через VPN";
        LblRoute.Text = "Весь компьютер · " + (_config.BypassRussia ? "Россия напрямую" : "Россия через сервер") + (_config.ExcludedApps.Count > 0 ? $" · Исключений: {_config.ExcludedApps.Count}" : "");
        LblPing.Text = on ? (_delay is int delay ? $"{delay} мс" : "—") : "—";
        if (_usage is not null)
        {
            LblDuration.Text = UsageTracker.Duration(_usage.ConnectedTime); LblTotalDuration.Text = "Всего " + UsageTracker.Duration(_usage.TotalTime);
            LblDownload.Text = "↓ " + (_usage.DownloadSpeed * 8 / 1_000_000).ToString("0.0", CultureInfo.CurrentCulture);
            LblUpload.Text = "↑ " + UsageTracker.Megabits(_usage.UploadSpeed);
            LblTraffic.Text = UsageTracker.Gigabytes(_usage.SessionUpload + _usage.SessionDownload);
            LblLifetime.Text = "Всего " + UsageTracker.Gigabytes(_usage.TotalUpload + _usage.TotalDownload);
            LblTransferred.Text = $"↓ {UsageTracker.Gigabytes(_usage.SessionDownload)}   ↑ {UsageTracker.Gigabytes(_usage.SessionUpload)}";
        }
        if (!on) LblConnections.Text = "Соединений: 0";
        LblChartEmpty.Visibility = _speeds.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        SpeedLine.Visibility = _speeds.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        if (_tray is not null) _tray.Text = on ? "Tiho · подключено" : _desired ? "Tiho · переподключение" : "Tiho · отключено";
    }

    private void Chart_SizeChanged(object sender, SizeChangedEventArgs e) => DrawChart();
    private void DrawChart()
    {
        if (SpeedLine?.Parent is not Grid graph || graph.ActualWidth <= 0) return;
        var values = _speeds.ToArray(); var max = Math.Max(1, values.DefaultIfEmpty().Max());
        LblChartScale.Text = values.Length == 0 ? "60 секунд" : $"До {max:0.0} Мбит/с · 60 с";
        var points = new PointCollection(); var width = graph.ActualWidth; var height = graph.ActualHeight - 4;
        for (var i = 0; i < 60; i++) { var index = i - (60 - values.Length); var value = index < 0 ? 0 : values[index]; points.Add(new Point(i * width / 59, height - value / max * height + 2)); }
        SpeedLine.Points = points;
    }
    private void ShowNotice(string message) { LblNotice.Text = message; Notice.Visibility = Visibility.Visible; }
    private static SolidColorBrush Brush(string hex) => new((Color)ColorConverter.ConvertFromString(hex));
    private async Task RunUiAsync(Func<Task> action)
    {
        try { await action(); }
        catch (OperationCanceledException) when (_closing) { }
        catch (Exception ex) { _log.Error("Tiho", ex.Message); ShowNotice(ex.Message); LblSettingsResult.Text = ex.Message; }
    }

    private void NetworkAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e)
    {
        if (_closing) return;
        Dispatcher.BeginInvoke(async () => { if (!_closing && _desired && e.IsAvailable) { _log.Sys("Сеть доступна. Восстанавливаю подключение."); await RunUiAsync(RestartAsync); } });
    }
    private void InitTray()
    {
        var resource = System.Windows.Application.GetResourceStream(new Uri("pack://application:,,,/Assets/app.ico"));
        if (resource is not null) { using var stream = resource.Stream; using var icon = new System.Drawing.Icon(stream); _icon = (System.Drawing.Icon)icon.Clone(); }
        _tray = new WinForms.NotifyIcon { Text = "Tiho", Icon = _icon ?? System.Drawing.SystemIcons.Application, Visible = true };
        _tray.DoubleClick += (_, _) => RestoreFromTray();
        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("Открыть Tiho", null, (_, _) => RestoreFromTray());
        menu.Items.Add("Подключить / отключить", null, async (_, _) => { if (_desired) await RunUiAsync(DisconnectAsync); else { _desired = true; await RunUiAsync(() => ConnectAsync()); } });
        menu.Items.Add("Выход", null, (_, _) => RequestExit());
        _tray.ContextMenuStrip = menu;
    }
    private void RestoreFromTray() { if (_closing || _windowClosed) return; Show(); WindowState = WindowState.Normal; Activate(); }
    public void RequestExit()
    {
        if (_closing || _windowClosed) return;
        _closing = true;
        Dispatcher.BeginInvoke(DispatcherPriority.Normal, new Action(() => { if (!_windowClosed) Close(); }));
    }
    protected override void OnClosed(EventArgs e) { _windowClosed = true; base.OnClosed(e); }
    private void Window_StateChanged(object sender, EventArgs e) { if (!_closing && _loaded && WindowState == WindowState.Minimized && _config.MinimizeToTray) { Hide(); WindowState = WindowState.Normal; } }
    private async void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_allowClose) return;
        e.Cancel = true;
        if (!_closing && _loaded && _config.MinimizeToTray) { Hide(); return; }
        if (_closing && _lifetime.IsCancellationRequested) return;
        _closing = true; _timer.Stop(); _desired = false; _connecting?.Cancel(); _lifetime.Cancel();
        NetworkChange.NetworkAvailabilityChanged -= NetworkAvailabilityChanged;
        try { await DisconnectAsync(); await _tunnel.DisposeAsync(); }
        catch (Exception ex) { _log.Error("Tiho", ex.Message); }
        finally
        {
            _tray?.Dispose(); _tray = null; _icon?.Dispose(); _icon = null;
            // StopAsync can finish synchronously. Always let this Closing event return
            // before asking WPF to close a second time; otherwise Close() throws.
            Dispatcher.BeginInvoke(DispatcherPriority.Normal, new Action(() =>
            {
                if (_windowClosed) return;
                _allowClose = true; Close();
            }));
        }
    }
}
