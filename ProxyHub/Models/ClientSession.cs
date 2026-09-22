namespace ProxyHub.Models;

public sealed class ClientSession
{
    public string Key { get; }
    public string DisplayName { get; set; }

    public int ActiveConnections;
    public long Requests;
    public long BytesUp;
    public long BytesDown;
    public long FirstSeenTicks;
    public long LastSeenTicks;
    public string LastHost = "";

    public ClientSession(string key, string displayName)
    {
        Key = key;
        DisplayName = displayName;
        var now = DateTime.Now.Ticks;
        FirstSeenTicks = now;
        LastSeenTicks = now;
    }

    public bool IsOnline => Volatile.Read(ref ActiveConnections) > 0;

    public void Touch()
        => Interlocked.Exchange(ref LastSeenTicks, DateTime.Now.Ticks);

    public void SetHost(string host)
        => LastHost = host;
}
