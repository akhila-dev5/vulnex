using Vulnex.Api;
using Xunit;

namespace Vulnex.Api.Tests;

public class SessionTests
{
    [Fact]
    public void Token_round_trips_and_can_be_dropped()
    {
        var store = new SessionStore(() => 60);
        var (token, session) = store.Create(new Dictionary<string, object?> { ["email"] = "a@b.c" }, "google", Cfg.RoleDeveloper);
        Assert.Equal(Cfg.RoleDeveloper, store.Get(token)!.Role);
        Assert.True(session.ExpiresAt > 0);
        Assert.True(store.Drop(token));
        Assert.Null(store.Get(token));
    }

    [Fact]
    public void Expired_session_is_gone()
    {
        var store = new SessionStore(() => -1);
        var (token, _) = store.Create(new Dictionary<string, object?>(), "google");
        Assert.Null(store.Get(token));
    }

    [Fact]
    public void Tokens_are_url_safe_and_unique()
    {
        var a = SessionStore.NewToken(32);
        var b = SessionStore.NewToken(32);
        Assert.NotEqual(a, b);
        Assert.DoesNotContain('+', a);
        Assert.DoesNotContain('/', a);
        Assert.DoesNotContain('=', a);
    }
}

public class RoleTests
{
    [Fact]
    public void Viewer_has_no_capabilities()
    {
        var flags = Roles.CapabilityFlags(Cfg.RoleViewer);
        Assert.All(flags.Values, v => Assert.Equal(false, v));
    }

    [Fact]
    public void Developer_cannot_approve_disputes_but_can_claim()
    {
        Assert.False(Roles.Has(Cfg.RoleDeveloper, "approve_dispute"));
        Assert.True(Roles.Has(Cfg.RoleDeveloper, "claim"));
    }

    [Fact]
    public void Automation_may_only_set_pr_and_run_jobs()
    {
        Assert.True(Roles.Has(Cfg.RoleAutomation, "set_pr"));
        Assert.True(Roles.Has(Cfg.RoleAutomation, "run_automation"));
        Assert.False(Roles.Has(Cfg.RoleAutomation, "claim"));
    }

    [Fact]
    public void Google_sign_in_needs_a_verified_email()
    {
        Assert.Null(Roles.GoogleRoleFor(Cfg.AdminEmail, false));
        Assert.Equal(Cfg.RoleAdmin, Roles.GoogleRoleFor(Cfg.AdminEmail.ToUpperInvariant(), true));
        Assert.Null(Roles.GoogleRoleFor("stranger@example.com", true));
    }
}

public class TriageTests
{
    [Fact]
    public void Website_links_are_in_a_stable_order()
    {
        var links = Triage.WebsiteLinks("cve-2024-1");
        Assert.Equal(6, links.Count);
        Assert.Equal("Ubuntu", links[0]["label"]);
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2024-1", links[5]["url"]);
    }

    [Fact]
    public void Affected_finding_with_upstream_fix_is_patch_available()
    {
        var finding = new Dictionary<string, object?> { ["status"] = "affected", ["upstream_fix"] = "https://github.com/x/y/commit/abc" };
        var result = Triage.PatchAvailability(finding);
        Assert.Equal("Patch Available", result["ai_verdict"]);
        Assert.Equal("https://github.com/x/y/commit/abc", result["patch_link"]);
    }

    [Fact]
    public void Patched_finding_is_not_applicable()
    {
        var finding = new Dictionary<string, object?> { ["status"] = "patched" };
        Assert.Equal("Not applicable", Triage.PatchAvailability(finding)["ai_verdict"]);
    }
}
