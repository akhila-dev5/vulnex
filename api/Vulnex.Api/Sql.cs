using System.Data;
using System.Globalization;

namespace Vulnex.Api;

/// <summary>Thrown when the configured database cannot be reached (maps to HTTP 503).</summary>
public sealed class DatabaseUnavailable : Exception
{
    public DatabaseUnavailable(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>Opens connections. The Npgsql-backed factory lives in <see cref="PgFactory"/>.</summary>
public interface IDbFactory
{
    DbConnection Open();
}

public static class Sql
{
    public static string UtcNow() =>
        DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture) + "+00:00";

    static DbCommand Build(DbConnection c, string sql, (string, object?)[] ps, DbTransaction? tx = null)
    {
        var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.Transaction = tx;
        foreach (var (name, value) in ps)
        {
            var p = cmd.CreateParameter();
            p.ParameterName = name;
            p.Value = value ?? DBNull.Value;
            cmd.Parameters.Add(p);
        }
        return cmd;
    }

    public static List<Row> Query(DbConnection c, string sql, params (string, object?)[] ps)
    {
        using var cmd = Build(c, sql, ps);
        using var r = cmd.ExecuteReader();
        var rows = new List<Row>();
        while (r.Read())
        {
            var row = new Row(r.FieldCount);
            for (var i = 0; i < r.FieldCount; i++)
                row[r.GetName(i)] = r.IsDBNull(i) ? null : r.GetValue(i);
            rows.Add(row);
        }
        return rows;
    }

    public static Row? One(DbConnection c, string sql, params (string, object?)[] ps) =>
        Query(c, sql, ps).FirstOrDefault();

    public static long Count(DbConnection c, string sql, params (string, object?)[] ps)
    {
        using var cmd = Build(c, sql, ps);
        var v = cmd.ExecuteScalar();
        return v is null or DBNull ? 0 : Convert.ToInt64(v, CultureInfo.InvariantCulture);
    }

    public static int Exec(DbConnection c, string sql, params (string, object?)[] ps)
    {
        using var cmd = Build(c, sql, ps);
        return cmd.ExecuteNonQuery();
    }

    /// <summary>INSERT ... RETURNING id, for tables with an integer id column.</summary>
    public static long Insert(DbConnection c, string sql, params (string, object?)[] ps)
    {
        using var cmd = Build(c, sql.TrimEnd().TrimEnd(';') + " RETURNING id", ps);
        return Convert.ToInt64(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    /// <summary>"@p0,@p1,..." for an IN list, adding the values to <paramref name="ps"/>.</summary>
    public static string InList(string prefix, IEnumerable<string> values, List<(string, object?)> ps)
    {
        var names = new List<string>();
        var i = 0;
        foreach (var v in values)
        {
            var n = $"{prefix}{i++}";
            names.Add("@" + n);
            ps.Add((n, v));
        }
        return string.Join(",", names);
    }

    // -- JSON-in-text helpers (the schema stores lists as JSON text) -------------
    public static object? Loads(object? value, Func<object?> fallback)
    {
        if (value is not string s) return fallback();
        try
        {
            return Json.ToPlain(System.Text.Json.JsonDocument.Parse(s).RootElement);
        }
        catch (System.Text.Json.JsonException)
        {
            return fallback();
        }
    }
}

public static class RowExt
{
    public static string Str(this Row r, string key) =>
        r.TryGetValue(key, out var v) && v is not null ? Convert.ToString(v, CultureInfo.InvariantCulture) ?? "" : "";

    public static long Long(this Row r, string key) =>
        r.TryGetValue(key, out var v) && v is not null ? Convert.ToInt64(v, CultureInfo.InvariantCulture) : 0;

    public static object? Get(this Row r, string key) => r.TryGetValue(key, out var v) ? v : null;

    public static Row? Sub(this Row r, string key) => r.Get(key) as Row;
}

public static class Json
{
    /// <summary>snake_case on the wire, like the Python API's field names.</summary>
    public static readonly System.Text.Json.JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
    };

    public static object? Loads(string text, object? fallback)
    {
        try { return ToPlain(System.Text.Json.JsonDocument.Parse(text).RootElement); }
        catch (System.Text.Json.JsonException) { return fallback; }
    }

    public static string Dumps(object? value) =>
        System.Text.Json.JsonSerializer.Serialize(value, new System.Text.Json.JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });

    /// <summary>Convert parsed JSON into plain CLR values (Row / List / string / double / long / bool / null).</summary>
    public static object? ToPlain(System.Text.Json.JsonElement e)
    {
        switch (e.ValueKind)
        {
            case System.Text.Json.JsonValueKind.Object:
                var row = new Row();
                foreach (var p in e.EnumerateObject()) row[p.Name] = ToPlain(p.Value);
                return row;
            case System.Text.Json.JsonValueKind.Array:
                return e.EnumerateArray().Select(ToPlain).ToList();
            case System.Text.Json.JsonValueKind.String:
                return e.GetString();
            case System.Text.Json.JsonValueKind.Number:
                return e.TryGetInt64(out var l) ? l : e.GetDouble();
            case System.Text.Json.JsonValueKind.True:
                return true;
            case System.Text.Json.JsonValueKind.False:
                return false;
            default:
                return null;
        }
    }
}
