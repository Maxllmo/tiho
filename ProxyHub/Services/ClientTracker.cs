using System.Collections.Concurrent;
using ProxyHub.Models;

namespace ProxyHub.Services;

public sealed class ClientTracker
{
    public const string PcKey = "PC";

    private readonly ConcurrentDictionary<string, ClientSession> _clients = new(StringComparer.OrdinalIgnoreCase);

    public int OnlineCount => _clients.Values.Count(c => c.IsOnline);

    public static string KeyFrom(IPEndPoint? ep)
    {
        if (ep is null || IsLoopback(ep.Address))
            return PcKey;

        var addr = ep.Address;
        if (addr.IsIPv4MappedToIPv6)
            addr = addr.MapToIPv4();
        return addr.ToString();
    }

    public static string DisplayName(string key)
        => key == PcKey ? "Этот ПК" : key;

    public ClientSession Begin(string key, string? displayName = null)
    {
        var session = _clients.GetOrAdd(key, k => new ClientSession(k, displayName ?? DisplayName(k)));
        if (!string.IsNullOrWhiteSpace(displayName))
            session.DisplayName = displayName;
        Interlocked.Increment(ref session.ActiveConnections);
        Interlocked.Increment(ref session.Requests);
        session.Touch();
        return session;
    }

    public void End(string key)
    {
        if (!_clients.TryGetValue(key, out var session))
            return;
        var left = Interlocked.Decrement(ref session.ActiveConnections);
        if (left < 0)
            Interlocked.Exchange(ref session.ActiveConnections, 0);
        session.Touch();
    }

    public void AddUp(ClientSession session, long bytes)
    {
        if (bytes <= 0) return;
        Interlocked.Add(ref session.BytesUp, bytes);
        session.Touch();
    }

    public void AddDown(ClientSession session, long bytes)
    {
        if (bytes <= 0) return;
        Interlocked.Add(ref session.BytesDown, bytes);
        session.Touch();
    }

    public IReadOnlyList<ClientSession> Snapshot()
        => _clients.Values
            .OrderByDescending(c => c.IsOnline)
            .ThenByDescending(c => Volatile.Read(ref c.LastSeenTicks))
            .ToList();

    private static bool IsLoopback(IPAddress addr)
    {
        if (IPAddress.IsLoopback(addr))
            return true;
        if (addr.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(addr.MapToIPv4()))
            return true;
        return false;
    }
}
