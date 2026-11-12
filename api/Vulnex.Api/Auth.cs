using System.Security.Cryptography;
using System.Text.Json;
using System.Web;

namespace Vulnex.Api;

/// <summary>One signed-in session (kept in memory, exactly like the Python backend).</summary>
public sealed record Session(string Role, string Method, Row Identity, double ExpiresAt);

public sealed class SessionStore
{
    readonly object _lock = new();
    readonly Dictionary<string, Session> _tokens = new();
    readonly Func<int> _ttl;

    public SessionStore(Func<int>? ttl = null) => _ttl = ttl ?? (() => Cfg.SessionTtlSeconds);

    static double Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;

    /// <summary>Same shape as Python's secrets.token_urlsafe(n).</summary>
    public static string NewToken(int bytes)
    {
        var buf = RandomNumberGenerator.GetBytes(bytes);
        return Convert.ToBase64String(buf).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public (string Token, Session Session) Create(Row identity, string method, string? role = null)
    {
        var token = NewToken(32);
        var session = new Session(role ?? Cfg.RoleAdmin, method, identity, Now() + _ttl());
        lock (_lock) _tokens[token] = session;
        return (token, session);
    }

    public Session? Get(string? token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        var now = Now();
        lock (_lock)
        {
            foreach (var key in _tokens.Where(kv => kv.Value.ExpiresAt <= now).Select(kv => kv.Key).ToList())
                _tokens.Remove(key);
            return _tokens.TryGetValue(token, out var s) ? s : null;
        }
    }

    public bool Drop(string? token)
    {
        if (string.IsNullOrEmpty(token)) return false;
        lock (_lock) return _tokens.Remove(token);
    }

    public void Clear() { lock (_lock) _tokens.Clear(); }
}

/// <summary>Short-lived OAuth <c>state</c> values so the callback cannot be forged.</summary>
public sealed class OAuthStates
{
    const double Ttl = 600;
    readonly object _lock = new();
    readonly Dictionary<string, double> _states = new();
    static double Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;

    public string New()
    {
        var state = SessionStore.NewToken(24);
        var now = Now();
        lock (_lock)
        {
            foreach (var key in _states.Where(kv => kv.Value <= now).Select(kv => kv.Key).ToList())
                _states.Remove(key);
            _states[state] = now + Ttl;
        }
        return state;
    }

    public bool Consume(string? state)
    {
        if (string.IsNullOrEmpty(state)) return false;
        double expiry;
        lock (_lock)
        {
            if (!_states.Remove(state, out expiry)) return false;
        }
        return expiry > Now();
    }
}

public static class Roles
{
    public static readonly IReadOnlyDictionary<string, HashSet<string>> Capabilities =
        new Dictionary<string, HashSet<string>>
        {
            [Cfg.RoleAdmin] = new()
            {
                "triage", "dispute", "comment", "scan", "assign", "patch_verdict", "set_pr",
                "approve_dispute", "rescore", "claim",
            },
            [Cfg.RoleDeveloper] = new() { "comment", "dispute", "set_pr", "claim" },
            [Cfg.RoleAutomation] = new() { "set_pr", "run_automation" },
            [Cfg.RoleViewer] = new(),
        };

    public static readonly HashSet<string> AssignableEmails = new(StringComparer.Ordinal)
    {
        "gurujuakhila.dev@gmail.com",
        "vulnexsecurityautomation@gmail.com",
        "dev1.vulnex@gmail.com",
        "dev2.vulnex@gmail.com",
        "dev3.vulnex@gmail.com",
    };

    public static bool Has(string role, string capability) =>
        Capabilities.TryGetValue(role, out var set) && set.Contains(capability);

    public static Row CapabilityFlags(string role) => new()
    {
        ["write_enabled"] = role == Cfg.RoleAdmin,
        ["can_comment"] = Has(role, "comment"),
        ["can_dispute"] = Has(role, "dispute"),
        ["can_triage"] = Has(role, "triage"),
        ["can_scan"] = Has(role, "scan"),
        ["can_set_patch_verdict"] = Has(role, "patch_verdict"),
        ["can_set_pr"] = Has(role, "set_pr"),
        ["can_assign"] = Has(role, "assign"),
        ["can_approve_dispute"] = Has(role, "approve_dispute"),
        ["can_rescore"] = Has(role, "rescore"),
        ["can_claim"] = Has(role, "claim"),
    };

    /// <summary>The role a verified Google account signs in with, or null when it may not.</summary>
    public static string? GoogleRoleFor(string? email, bool verified)
    {
        if (!(verified && !string.IsNullOrEmpty(email))) return null;
        var lowered = email!.Trim().ToLowerInvariant();
        if (lowered == Cfg.AdminEmailAllowlist) return Cfg.RoleAdmin;
        if (Cfg.DeveloperEmails.Contains(lowered)) return Cfg.RoleDeveloper;
        return null;
    }
}

/// <summary>Raised to produce an HTTP error with a Python-style <c>{"detail": ...}</c> body.</summary>
public sealed class HttpError : Exception
{
    public int Status { get; }
    public HttpError(int status, string detail) : base(detail) => Status = status;
}

/// <summary>Resolves the caller's role from the X-VULNEX-Key header.</summary>
public sealed class AuthService
{
    public SessionStore Sessions { get; }
    public OAuthStates States { get; } = new();
    readonly HttpClient _http;

    public AuthService(SessionStore sessions, HttpClient http)
    {
        Sessions = sessions;
        _http = http;
    }

    public static string? Credential(HttpRequest request)
    {
        var v = request.Headers["X-VULNEX-Key"].ToString();
        return string.IsNullOrEmpty(v) ? null : v;
    }

    public string ResolveRole(HttpRequest request)
    {
        var credential = Credential(request);
        if (credential is null) return Cfg.RoleViewer;
        var session = Sessions.Get(credential);
        if (session is not null) return string.IsNullOrEmpty(session.Role) ? Cfg.RoleAdmin : session.Role;
        return Cfg.RoleForKey(credential);
    }

    public string RequireAdmin(HttpRequest request)
    {
        var role = ResolveRole(request);
        if (role != Cfg.RoleAdmin)
            throw new HttpError(401, "Read-only access: this action needs an admin sign-in. Sign in with Google and retry.");
        return role;
    }

    public string RequireCapability(HttpRequest request, string capability, string what)
    {
        var role = ResolveRole(request);
        if (!Roles.Has(role, capability))
            throw new HttpError(401, $"Sign in with Google to {what}. Read-only visitors cannot do this.");
        return role;
    }

    public string RequirePrSetter(HttpRequest request)
    {
        var role = ResolveRole(request);
        if (!Roles.Has(role, "set_pr"))
            throw new HttpError(401, "Setting the GitHub CVE PR needs a developer or admin sign-in.");
        return role;
    }

    public (string Role, string Email) RequireClaimer(HttpRequest request)
    {
        var role = ResolveRole(request);
        if (!Roles.Has(role, "claim"))
            throw new HttpError(401, "Only developers and the administrator can claim or track CVEs.");
        return (role, ActorIdentity(request, role).Trim().ToLowerInvariant());
    }

    public void RequireAutomation(HttpRequest request)
    {
        if (!Roles.Has(ResolveRole(request), "run_automation"))
            throw new HttpError(401, "Only the automation key can do this.");
    }

    /// <summary>Who to record as the author of a change: the signed-in email, else the role's name.</summary>
    public string ActorIdentity(HttpRequest request, string role)
    {
        var session = Sessions.Get(Credential(request));
        var email = session?.Identity.GetValueOrDefault("email") as string;
        if (!string.IsNullOrEmpty(email)) return email!;
        var fallback = Cfg.IdentityFor(role).GetValueOrDefault("identity") as string;
        return !string.IsNullOrEmpty(fallback) ? fallback! : role;
    }

    // -- Google OAuth -------------------------------------------------------
    public static string AuthorizeUrl(string redirectUri, string state)
    {
        var q = HttpUtility.ParseQueryString(string.Empty);
        q["client_id"] = Cfg.GoogleClientId;
        q["redirect_uri"] = redirectUri;
        q["scope"] = "openid email profile";
        q["response_type"] = "code";
        q["access_type"] = "online";
        q["state"] = state;
        q["include_granted_scopes"] = "true";
        return "https://accounts.google.com/o/oauth2/v2/auth?" + q;
    }

    /// <summary>Swap an OAuth code for the Google profile, or null when anything fails.</summary>
    public async Task<JsonElement?> ExchangeAsync(string code, string redirectUri)
    {
        if (!Cfg.GoogleLoginConfigured) return null;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Cfg.HttpTimeoutSeconds));
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = Cfg.GoogleClientId,
                ["client_secret"] = Cfg.GoogleClientSecret,
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["grant_type"] = "authorization_code",
            });
            using var tokenResp = await _http.PostAsync("https://oauth2.googleapis.com/token", form, cts.Token);
            tokenResp.EnsureSuccessStatusCode();
            using var tokenDoc = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync(cts.Token));
            if (!tokenDoc.RootElement.TryGetProperty("access_token", out var at) || at.ValueKind != JsonValueKind.String)
                return null;
            using var req = new HttpRequestMessage(HttpMethod.Get, "https://openidconnect.googleapis.com/v1/userinfo");
            req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", at.GetString());
            using var userResp = await _http.SendAsync(req, cts.Token);
            userResp.EnsureSuccessStatusCode();
            var profile = JsonDocument.Parse(await userResp.Content.ReadAsStringAsync(cts.Token)).RootElement.Clone();
            if (profile.TryGetProperty("email", out var em) && em.ValueKind == JsonValueKind.String &&
                profile.TryGetProperty("email_verified", out var ev) && ev.ValueKind == JsonValueKind.True)
                return profile;
            return null;
        }
        catch
        {
            return null;
        }
    }
}
