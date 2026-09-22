using System.Windows;
using System.Windows.Controls;
using ProxyHub.Models;
using ProxyHub.Services;

namespace ProxyHub;

public sealed class AddServerResult
{
    public List<ServerProfile> Profiles { get; } = new();
    public Subscription? Subscription { get; set; }
}

public partial class AddServerWindow : Window
{
    public AddServerResult? Result { get; private set; }

    public AddServerWindow()
    {
        InitializeComponent();
    }

    public static AddServerWindow ForProxy() => new();

    public static AddServerWindow ForVpn(string? clipboard = null)
    {
        var w = new AddServerWindow();
        w.RadVpn.IsChecked = true;
        if (!string.IsNullOrWhiteSpace(clipboard))
            w.TxtVpn.Text = clipboard;
        return w;
    }

    public static AddServerWindow ForSubscription()
    {
        var w = new AddServerWindow();
        w.RadSub.IsChecked = true;
        return w;
    }

    private void Mode_Changed(object sender, RoutedEventArgs e)
    {
        if (PanelProxy is null)
            return;
        PanelProxy.Visibility = RadProxy.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelVpn.Visibility = RadVpn.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelSub.Visibility = RadSub.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
    }

    private void BtnCancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void BtnOk_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var result = new AddServerResult();
            if (RadProxy.IsChecked == true)
            {
                var host = TxtHost.Text.Trim();
                var port = ParsePort(TxtPort.Text, 0);
                if (string.IsNullOrWhiteSpace(host) || port == 0)
                    throw new InvalidOperationException("Укажите сервер и порт.");

                var type = (CmbType.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "SOCKS5";
                var name = TxtName.Text.Trim();
                result.Profiles.Add(new ServerProfile
                {
                    Name = string.IsNullOrWhiteSpace(name) ? $"{host}:{port}" : name,
                    Kind = "proxy",
                    Protocol = type,
                    Host = host,
                    Port = port,
                    Username = TxtUser.Text.Trim(),
                    Password = TxtPass.Password
                });
            }
            else if (RadVpn.IsChecked == true)
            {
                var profiles = ShareLinkParser.ParseMany(TxtVpn.Text);
                if (profiles.Count == 0)
                    throw new InvalidOperationException("Не найдено ни одной поддерживаемой ссылки.");
                result.Profiles.AddRange(profiles);
            }
            else
            {
                var url = TxtSubUrl.Text.Trim();
                if (string.IsNullOrWhiteSpace(url))
                    throw new InvalidOperationException("Вставьте ссылку подписки.");
                var name = TxtSubName.Text.Trim();
                result.Subscription = new Subscription
                {
                    Name = string.IsNullOrWhiteSpace(name) ? "Подписка" : name,
                    Url = url
                };
            }

            Result = result;
            DialogResult = true;
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Добавить сервер", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static int ParsePort(string text, int fallback)
        => int.TryParse(text.Trim(), out var p) && p is > 0 and <= 65535 ? p : fallback;
}
