using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Vulnex.Api;

namespace Vulnex.Api.Tests;

/// <summary>Everyone the tests sign in as. Developer emails are handed to the app through the environment.</summary>
public static class Who
{
    public const string Dev = "dev.one@example.org";
    public const string Other = "dev.two@example.org";
    public const string KeyHeader = "X-VULNEX-Key";
    public const string AutomationKey = "ci-automation-key";
}

/// <summary>
/// Starts the real API in memory (no network port) against the PostgreSQL database in DATABASE_URL.
/// That database must hold the rows created by <c>scripts/api_snapshots.py seed</c>.
/// </summary>
public sealed class ApiFactory : WebApplicationFactory<Program>
{
    public ApiFactory()
    {
        // The app reads its settings from the environment at request time, like on Render.
        Environment.SetEnvironmentVariable("VULNEX_AUTOMATION_KEY", Who.AutomationKey);
        Environment.SetEnvironmentVariable("VULNEX_DEVELOPER_EMAILS", $"{Who.Dev},{Who.Other}");
        Environment.SetEnvironmentVariable("GOOGLE_OAUTH_CLIENT_ID", "");
        Environment.SetEnvironmentVariable("GOOGLE_OAUTH_CLIENT_SECRET", "");
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DATABASE_URL")))
            throw new InvalidOperationException(
                "DATABASE_URL must point at a PostgreSQL database seeded with scripts/api_snapshots.py seed.");
    }

    /// <summary>A real session token, as Google sign-in would mint for this account.</summary>
    public string Token(string email, string role)
    {
        var identity = Cfg.IdentityFor(role == Cfg.RoleAdmin ? Cfg.RoleAdmin : Cfg.RoleDeveloper);
        if (role != Cfg.RoleAdmin)
        {
            identity["identity"] = email;
            identity["email"] = email;
        }
        return Services.GetRequiredService<SessionStore>().Create(identity, "google", role).Token;
    }

    public string AdminToken() => Token(Cfg.AdminEmail, Cfg.RoleAdmin);

    /// <summary>Forget everything people typed (comments, claims, disputes, rescores) and any cached answers.</summary>
    public void ResetTriage()
    {
        using var conn = Services.GetRequiredService<IDbFactory>().Open();
        Sql.Exec(conn,
            "TRUNCATE finding_triage, finding_comments, disputes, assignments, assignment_comments, " +
            "cve_rescores, automation_requests RESTART IDENTITY");
        Services.GetRequiredService<ResponseCache>().Clear();
        Services.GetRequiredService<SessionStore>().Clear();
    }
}

public sealed record Reply(HttpStatusCode Status, JsonNode? Body)
{
    public int Code => (int)Status;
    public JsonNode? At(string path) => Body.At(path);
}

public static class Http
{
    public static async Task<Reply> Get(this HttpClient client, string path, string? token = null)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null) req.Headers.Add(Who.KeyHeader, token);
        return await Send(client, req);
    }

    public static async Task<Reply> Post(this HttpClient client, string path, object? body = null, string? token = null)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(JsonSerializer.Serialize(body ?? new { }), Encoding.UTF8, "application/json"),
        };
        if (token is not null) req.Headers.Add(Who.KeyHeader, token);
        return await Send(client, req);
    }

    static async Task<Reply> Send(HttpClient client, HttpRequestMessage req)
    {
        using var resp = await client.SendAsync(req);
        var text = await resp.Content.ReadAsStringAsync();
        JsonNode? body = null;
        if (text.Length > 0)
        {
            try { body = JsonNode.Parse(text); } catch (JsonException) { body = JsonValue.Create(text); }
        }
        return new Reply(resp.StatusCode, body);
    }

    /// <summary>Walk a JSON tree with a dotted path: "items.0.triage.owner".</summary>
    public static JsonNode? At(this JsonNode? node, string path)
    {
        foreach (var part in path.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            if (node is JsonArray arr && int.TryParse(part, out var i)) node = i < arr.Count ? arr[i] : null;
            else if (node is JsonObject obj) node = obj[part];
            else return null;
        }
        return node;
    }

    public static string? Text(this JsonNode? node) =>
        node is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    public static bool Flag(this JsonNode? node) =>
        node is JsonValue v && v.TryGetValue<bool>(out var b) && b;

    public static double Number(this JsonNode? node) =>
        node is JsonValue v && v.TryGetValue<double>(out var d) ? d : double.NaN;
}
