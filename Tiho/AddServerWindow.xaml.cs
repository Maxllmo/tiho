using System.Windows;
using System.Windows.Controls;
using Tiho.Models;

namespace Tiho;

public partial class AddServerWindow : Window
{
    private readonly string? _id;
    public ServerProfile? Result { get; private set; }
    public AddServerWindow(ServerProfile? profile = null)
    {
        InitializeComponent();
        if (profile is null) return;
        _id = profile.Id; TxtName.Text = profile.Name; TxtHost.Text = profile.Host; TxtPort.Text = profile.Port.ToString();
        TxtUser.Text = profile.Username; TxtPass.Password = profile.Password; CmbType.SelectedIndex = profile.Protocol == "SOCKS5" ? 1 : 0;
    }
    private void BtnCancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
    private void BtnOk_Click(object sender, RoutedEventArgs e)
    {
        var host = TxtHost.Text.Trim().Trim('[', ']');
        if (string.IsNullOrWhiteSpace(host) || host.Contains('/') || host.Any(char.IsWhiteSpace) || !int.TryParse(TxtPort.Text, out var port) || port is <= 0 or > 65535)
        { MessageBox.Show("Укажите адрес сервера без http:// и порт от 1 до 65535.", "Tiho"); return; }
        Result = new ServerProfile
        {
            Name = string.IsNullOrWhiteSpace(TxtName.Text) ? host : TxtName.Text.Trim(), Kind = "proxy",
            Protocol = ((ComboBoxItem)CmbType.SelectedItem).Content.ToString()!, Host = host, Port = port,
            Username = TxtUser.Text.Trim(), Password = TxtPass.Password
        };
        if (_id is not null) Result.Id = _id;
        DialogResult = true;
    }
}
