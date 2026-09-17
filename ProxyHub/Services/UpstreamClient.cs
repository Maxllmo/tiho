using System.IO;
using System.Net.Sockets;
using System.Text;
using ProxyHub.Models;

namespace ProxyHub.Services;

public static class UpstreamClient
{
    public static async Task<Stream> OpenAsync(AppConfig config, string host, int port, bool bypass, CancellationToken ct)
    {
        if (bypass)
            return await ConnectDirectAsync(host, port, ct);

        if (!config.IsConfigured)
            throw new InvalidOperationException("Не задан upstream-прокси Amnezia.");

        return config.UpstreamType.Equals("HTTP", StringComparison.OrdinalIgnoreCase)
            ? await ConnectHttpAsync(config, host, port, ct)
            : await ConnectSocks5Async(config, host, port, ct);
    }

    public static async Task<Stream> ConnectDirectAsync(string host, int port, CancellationToken ct)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await tcp.ConnectAsync(host, port, timeout.Token);
            return new TcpOwnedStream(tcp);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    private static async Task<Stream> ConnectSocks5Async(AppConfig config, string host, int port, CancellationToken ct)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await tcp.ConnectAsync(config.Host.Trim(), config.Port, timeout.Token);
            var stream = tcp.GetStream();

            var user = config.Username ?? "";
            var pass = config.Password ?? "";
            var hasAuth = user.Length > 0;

            await stream.WriteAsync(hasAuth ? new byte[] { 5, 2, 0, 2 } : new byte[] { 5, 1, 0 }, timeout.Token);
            var method = await ReadExactAsync(stream, 2, timeout.Token);
            if (method[0] != 5)
                throw new IOException("Сервер не говорит на SOCKS5.");

            if (method[1] == 2)
            {
                var u = Encoding.UTF8.GetBytes(user);
                var p = Encoding.UTF8.GetBytes(pass);
                if (u.Length > 255 || p.Length > 255)
                    throw new IOException("Слишком длинный логин или пароль SOCKS5.");

                var auth = new byte[3 + u.Length + p.Length];
                auth[0] = 1;
                auth[1] = (byte)u.Length;
                Buffer.BlockCopy(u, 0, auth, 2, u.Length);
                auth[2 + u.Length] = (byte)p.Length;
                Buffer.BlockCopy(p, 0, auth, 3 + u.Length, p.Length);
                await stream.WriteAsync(auth, timeout.Token);
                var authResp = await ReadExactAsync(stream, 2, timeout.Token);
                if (authResp[1] != 0)
                    throw new IOException("SOCKS5: логин или пароль отклонены.");
            }
            else if (method[1] != 0)
            {
                throw new IOException(method[1] == 0xFF
                    ? "SOCKS5: сервер не принял метод авторизации."
                    : $"SOCKS5: неизвестный метод {method[1]}.");
            }

            var hostBytes = Encoding.UTF8.GetBytes(host);
            if (hostBytes.Length > 255)
                throw new IOException("Имя хоста слишком длинное для SOCKS5.");

            var req = new byte[7 + hostBytes.Length];
            req[0] = 5;
            req[1] = 1;
            req[2] = 0;
            req[3] = 3;
            req[4] = (byte)hostBytes.Length;
            Buffer.BlockCopy(hostBytes, 0, req, 5, hostBytes.Length);
            req[5 + hostBytes.Length] = (byte)(port >> 8);
            req[6 + hostBytes.Length] = (byte)port;
            await stream.WriteAsync(req, timeout.Token);

            var reply = await ReadExactAsync(stream, 4, timeout.Token);
            if (reply[1] != 0)
                throw new IOException($"SOCKS5 не смог открыть {host}:{port} (код {reply[1]}).");

            await DrainBindAddressAsync(stream, reply[3], timeout.Token);
            return new TcpOwnedStream(tcp);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    private static async Task DrainBindAddressAsync(NetworkStream stream, byte atyp, CancellationToken ct)
    {
        switch (atyp)
        {
            case 1:
                await ReadExactAsync(stream, 4 + 2, ct);
                break;
            case 4:
                await ReadExactAsync(stream, 16 + 2, ct);
                break;
            case 3:
                var len = await ReadExactAsync(stream, 1, ct);
                await ReadExactAsync(stream, len[0] + 2, ct);
                break;
            default:
                throw new IOException($"SOCKS5: неизвестный ATYP {atyp}.");
        }
    }

    private static async Task<Stream> ConnectHttpAsync(AppConfig config, string host, int port, CancellationToken ct)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await tcp.ConnectAsync(config.Host.Trim(), config.Port, timeout.Token);
            var stream = tcp.GetStream();

            var sb = new StringBuilder();
            sb.Append($"CONNECT {host}:{port} HTTP/1.1\r\n");
            sb.Append($"Host: {host}:{port}\r\n");
            AppendProxyAuthorization(sb, config);
            sb.Append("Proxy-Connection: Keep-Alive\r\n\r\n");

            await stream.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), timeout.Token);

            var headers = await ReadUntilAsync(stream, "\r\n\r\n"u8.ToArray(), 65536, timeout.Token);
            ThrowIfHttpConnectFailed(Encoding.ASCII.GetString(headers), port);

            return new TcpOwnedStream(tcp);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    public static async Task<Stream> ConnectHttpProxyAsync(AppConfig config, CancellationToken ct)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await tcp.ConnectAsync(config.Host.Trim(), config.Port, timeout.Token);
            return new TcpOwnedStream(tcp);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    public static void AppendProxyAuthorization(StringBuilder sb, AppConfig config)
    {
        if (string.IsNullOrEmpty(config.Username))
            return;
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{config.Username}:{config.Password}"));
        sb.Append($"Proxy-Authorization: Basic {token}\r\n");
    }

    private static void ThrowIfHttpConnectFailed(string headerText, int port)
    {
        var first = headerText.Split('\n')[0].Trim();
        var parts = first.Split(' ');
        var code = parts.Length >= 2 && int.TryParse(parts[1], out var n) ? n : 0;
        if (code is >= 200 and < 300)
            return;

        var message = code switch
        {
            407 => "HTTP-прокси отклонил логин или пароль.",
            401 => "HTTP-прокси требует авторизацию.",
            403 => $"HTTP-прокси запретил CONNECT к порту {port} (403).",
            405 => $"HTTP-прокси не умеет CONNECT к порту {port} (405).",
            501 => $"HTTP-прокси не умеет CONNECT к порту {port} (501).",
            _ => $"HTTP-прокси ответил: {first}"
        };

        if (code is 403 or 405 or 501)
            throw new HttpConnectDeniedException(code, port, message);
        throw new IOException(message);
    }

    public static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken ct)
    {
        var buf = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var n = await stream.ReadAsync(buf.AsMemory(offset, count - offset), ct);
            if (n == 0)
                throw new IOException("Соединение закрыто.");
            offset += n;
        }
        return buf;
    }

    public static async Task<byte[]> ReadUntilAsync(Stream stream, byte[] needle, int max, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        var buf = new byte[1024];
        while (ms.Length < max)
        {
            var n = await stream.ReadAsync(buf, ct);
            if (n == 0)
                throw new IOException("Соединение закрыто до конца заголовков.");
            ms.Write(buf, 0, n);
            var data = ms.ToArray();
            var idx = IndexOf(data, needle);
            if (idx >= 0)
            {
                var headers = new byte[idx + needle.Length];
                Buffer.BlockCopy(data, 0, headers, 0, headers.Length);
                return headers;
            }
        }
        throw new IOException("Слишком большие заголовки.");
    }

    public static int IndexOf(byte[] haystack, byte[] needle)
    {
        var max = haystack.Length - needle.Length;
        for (var i = 0; i <= max; i++)
        {
            var found = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    found = false;
                    break;
                }
            }
            if (found)
                return i;
        }
        return -1;
    }

    internal sealed class TcpOwnedStream : Stream
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _stream;

        public TcpOwnedStream(TcpClient client)
        {
            _client = client;
            _stream = client.GetStream();
        }

        public override bool CanRead => _stream.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => _stream.CanWrite;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => _stream.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => _stream.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) => _stream.Read(buffer, offset, count);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _stream.ReadAsync(buffer, offset, count, cancellationToken);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _stream.ReadAsync(buffer, cancellationToken);
        public override void Write(byte[] buffer, int offset, int count) => _stream.Write(buffer, offset, count);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _stream.WriteAsync(buffer, offset, count, cancellationToken);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _stream.WriteAsync(buffer, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _stream.Dispose();
                _client.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}

public sealed class HttpConnectDeniedException : IOException
{
    public int StatusCode { get; }
    public int Port { get; }

    public HttpConnectDeniedException(int statusCode, int port, string message)
        : base(message)
    {
        StatusCode = statusCode;
        Port = port;
    }
}
