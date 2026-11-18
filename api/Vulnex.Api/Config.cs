using System.Security.Cryptography;
using System.Text;

namespace Vulnex.Api;

/// <summary>
/// Runtime configuration. Every environment variable keeps the exact name the
/// Python backend used, so an existing Render / GitHub secret set works unchanged.
/// </summary>
public static class Cfg
{
    static string Env(string name, string fallback = "") =>
        Environment.GetEnvironmentVariable(name) ?? fallback;

    static List<string> CsvEnv(string name, string fallback = "") =>
        Env(name, fallback).Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList();

    public const string Version = "1.0.0";

    public static string DatabaseUrl => Env("DATABASE_URL").Trim();

    public static string RepoOwner => Env("VULNEX_REPO_OWNER", "akhila-dev5");
    public static string RepoName => Env("VULNEX_REPO_NAME", "azurelinux-test");
    public static List<string> DefaultBranches => CsvEnv("VULNEX_BRANCHES", "3.0,4.0");
    public static string OsvEcosystem => Env("VULNEX_OSV_ECOSYSTEM", "Azure Linux:3");
    public static string PatchTargetRepo => Env("VULNEX_PATCH_TARGET_REPO", "akhila-dev5/azurelinux-test");

    public const string OpenStatus = "affected";

    public const string RoleViewer = "viewer";
    public const string RoleAdmin = "admin";
    public const string RoleAutomation = "automation";
    public const string RoleDeveloper = "developer";

    // Fixed in code on purpose (same as the Python backend): no environment value may
    // silently grant administrator access to another account.
    public const string AdminIdentity = "gurujuakhila.dev@gmail.com";
    public const string AdminEmail = "gurujuakhila.dev@gmail.com";
    public const string AdminEmailAllowlist = "gurujuakhila.dev@gmail.com";

    public static readonly string[] BuiltInDeveloperEmails = { "vulnexsecurityautomation@gmail.com" };

    public static HashSet<string> DeveloperEmails
    {
        get
        {
            var set = new HashSet<string>(BuiltInDeveloperEmails, StringComparer.Ordinal);
            foreach (var e in CsvEnv("VULNEX_DEVELOPER_EMAILS")) set.Add(e.ToLowerInvariant());
            return set;
        }
    }

    public static string GoogleClientId => Env("GOOGLE_OAUTH_CLIENT_ID").Trim();
    public static string GoogleClientSecret => Env("GOOGLE_OAUTH_CLIENT_SECRET").Trim();
    public static string GoogleRedirect => Env("VULNEX_GOOGLE_REDIRECT").Trim();

    public static string AutomationIdentity => Env("VULNEX_AUTOMATION_IDENTITY", "vulnex-sec");
    public static string AutomationEmail => Env("VULNEX_AUTOMATION_EMAIL", "vulnexsecurityautomation@gmail.com");
    public static string AutomationKey => Env("VULNEX_AUTOMATION_KEY");
    public static string DispatchToken => Env("VULNEX_DISPATCH_TOKEN");
    public static string DispatchRepo => Env("VULNEX_DISPATCH_REPO", "akhila-dev5/vulnex");

    public static int SessionTtlSeconds =>
        int.TryParse(Env("VULNEX_SESSION_TTL"), out var v) ? v : 12 * 3600;

    public static List<string> AllowedOrigins => CsvEnv("VULNEX_ALLOWED_ORIGINS");

    public static int HttpTimeoutSeconds =>
        int.TryParse(Env("VULNEX_HTTP_TIMEOUT"), out var v) ? v : 30;

    static string GithubRaw => "https://raw.githubusercontent.com";
    static string VulnDataRepo => Env("VULNEX_VULNERABILITYDATA_REPO", "akhila-dev5/VulnerabilityData");
    static string VulnDataBranch => Env("VULNEX_VULNERABILITYDATA_BRANCH", "main");
    public static string VulnDataJsonUrl => Env("VULNEX_VULNERABILITYDATA_JSON",
        $"{GithubRaw}/{VulnDataRepo}/{VulnDataBranch}/data/azurelinux-test.json");
    public static string VulnDataOvalUrl => Env("VULNEX_VULNERABILITYDATA_OVAL",
        $"{GithubRaw}/{VulnDataRepo}/{VulnDataBranch}/oval/azurelinux-test.xml");

    /// <summary>Where the built React app lives (Docker image sets VULNEX_FRONTEND_DIR).</summary>
    public static string FrontendDir => Env("VULNEX_FRONTEND_DIR");

    public static bool GoogleLoginConfigured => GoogleClientId.Length > 0 && GoogleClientSecret.Length > 0;

    /// <summary>Constant-time compare of a presented machine key with the automation key.</summary>
    public static string RoleForKey(string? presented)
    {
        if (string.IsNullOrEmpty(presented)) return RoleViewer;
        var key = AutomationKey;
        if (key.Length > 0 && FixedTimeEquals(presented, key)) return RoleAutomation;
        return RoleViewer;
    }

    static bool FixedTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    public static Row IdentityFor(string role) => role switch
    {
        RoleAdmin => new Row { ["identity"] = AdminIdentity, ["email"] = AdminEmail, ["kind"] = "admin" },
        RoleAutomation => new Row { ["identity"] = AutomationIdentity, ["email"] = AutomationEmail, ["kind"] = "automation" },
        RoleDeveloper => new Row { ["identity"] = "developer", ["email"] = "", ["kind"] = "developer" },
        _ => new Row { ["identity"] = "anonymous", ["email"] = "", ["kind"] = "viewer" },
    };

    public static Row RepositoryMetadata() => new()
    {
        ["owner"] = RepoOwner,
        ["repo"] = RepoName,
        ["branches"] = DefaultBranches,
        ["ecosystem"] = OsvEcosystem,
        ["patch_target_repo"] = PatchTargetRepo,
        ["vulnerability_data"] = VulnDataJsonUrl,
        ["vulnerability_data_oval"] = VulnDataOvalUrl,
    };

    public static Row RolesMetadata() => new()
    {
        ["admin"] = new Row
        {
            ["identity"] = AdminIdentity,
            ["email"] = AdminEmail,
            ["capabilities"] = new[] { "triage", "dispute", "comment", "scan", "assign", "patch_verdict", "set_pr" },
        },
        ["automation"] = new Row
        {
            ["identity"] = AutomationIdentity,
            ["email"] = AutomationEmail,
            ["capabilities"] = new[] { "set_pr" },
        },
    };
}
