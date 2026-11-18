namespace Vulnex.Api;

/// <summary>
/// A tiny in-memory cache for read-heavy responses (60 s), dropped on every write.
/// Same behaviour as the Python backend's cache.py.
/// </summary>
public sealed class ResponseCache
{
    public static readonly TimeSpan Ttl = TimeSpan.FromSeconds(60);
    readonly object _lock = new();
    readonly Dictionary<string, (DateTime At, object Value)> _store = new();

    public T Cached<T>(string key, Func<T> compute) where T : notnull
    {
        lock (_lock)
        {
            if (_store.TryGetValue(key, out var hit) && DateTime.UtcNow - hit.At < Ttl)
                return (T)hit.Value;
        }
        var value = compute();
        lock (_lock) _store[key] = (DateTime.UtcNow, value);
        return value;
    }

    public void Clear() { lock (_lock) _store.Clear(); }
}
