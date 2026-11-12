using Npgsql;

namespace Vulnex.Api;

/// <summary>
/// The only file that touches Npgsql. It accepts the same DATABASE_URL the Python
/// backend used (postgresql://user:pass@host:port/db?sslmode=...), including the
/// Supabase Session-pooler string.
/// </summary>
public sealed class PgFactory : IDbFactory
{
    readonly NpgsqlDataSource _source;
    readonly string _url;

    public PgFactory(string url)
    {
        _url = url;
        _source = NpgsqlDataSource.Create(ToConnectionString(url));
    }

    public static string ToConnectionString(string url)
    {
        url = url.Trim();
        if (url.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase))
            url = "postgresql://" + url["postgres://".Length..];
        var uri = new Uri(url);
        var userInfo = uri.UserInfo.Split(':', 2);
        var host = uri.Host;
        var local = host is "localhost" or "127.0.0.1" or "::1" or "";
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        var sslmode = (query["sslmode"] ?? (local ? "disable" : "require")).ToLowerInvariant();

        var b = new NpgsqlConnectionStringBuilder
        {
            Host = host,
            Port = uri.Port > 0 ? uri.Port : 5432,
            Database = uri.AbsolutePath.Trim('/'),
            Username = Uri.UnescapeDataString(userInfo[0]),
            Password = userInfo.Length > 1 ? Uri.UnescapeDataString(userInfo[1]) : null,
            Timeout = 10,
            MaxPoolSize = 5,
            // Supabase's pooler cannot use server-side prepared statements.
            MaxAutoPrepare = 0,
            NoResetOnClose = true,
        };
        switch (sslmode)
        {
            case "disable":
                b.SslMode = SslMode.Disable;
                break;
            case "verify-full":
                b.SslMode = SslMode.VerifyFull;
                break;
            case "verify-ca":
                b.SslMode = SslMode.VerifyCA;
                break;
            default: // require / prefer / allow behave like libpq: encrypt, don't verify
                b.SslMode = sslmode == "require" ? SslMode.Require : SslMode.Prefer;
                b.TrustServerCertificate = true;
                break;
        }
        return b.ConnectionString;
    }

    public DbConnection Open()
    {
        try
        {
            return _source.OpenConnection();
        }
        catch (Exception ex) when (ex is NpgsqlException or TimeoutException or System.Net.Sockets.SocketException or InvalidOperationException)
        {
            throw new DatabaseUnavailable(Hint(_url), ex);
        }
    }

    /// <summary>A short, secret-free explanation of the most likely cause.</summary>
    public static string Hint(string url)
    {
        string host;
        try { host = new Uri(url.Replace("postgres://", "postgresql://")).Host; } catch { host = ""; }
        if (System.Text.RegularExpressions.Regex.IsMatch(host, @"^db\.[a-z0-9]+\.supabase\.co$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            return $"'{host}' is Supabase's direct connection, which is IPv6-only and cannot be reached from Render or GitHub Actions. " +
                   "In Supabase choose Connect -> Session pooler and use that connection string (host like aws-0-<region>.pooler.supabase.com) as DATABASE_URL.";
        return $"Could not connect to '{(host.Length > 0 ? host : "the database host")}'. Check DATABASE_URL (host, port, user, password; encode '@' in the password as %40) and that the database is running.";
    }
}
