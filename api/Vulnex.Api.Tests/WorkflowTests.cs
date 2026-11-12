using System.Net;
using Xunit;

namespace Vulnex.Api.Tests;

[CollectionDefinition("database")]
public class DatabaseCollection : ICollectionFixture<ApiFactory> { }

/// <summary>
/// Who may do what, and what each write does. Ported from the old Python API tests
/// (test_access, test_disputes, test_claim_workflows, test_rescore_and_scores).
/// All tests share one database, so they run one after another and each starts from a clean slate.
/// </summary>
[Collection("database")]
[Trait("Suite", "Workflow")]
public class WorkflowTests
{
    // One of the seeded findings: package "beta", branch 3.0.
    static readonly object Finding = new { cve_id = "CVE-2024-0002", branch = "3.0", spec_path = "SPECS/beta/beta.spec" };
    const string FindingCve = "CVE-2024-0002";

    readonly ApiFactory _f;
    readonly HttpClient _c;
    readonly string _admin;
    readonly string _dev;
    readonly string _other;

    public WorkflowTests(ApiFactory factory)
    {
        _f = factory;
        _f.ResetTriage();
        _c = _f.CreateClient();
        _admin = _f.AdminToken();
        _dev = _f.Token(Who.Dev, Cfg.RoleDeveloper);
        _other = _f.Token(Who.Other, Cfg.RoleDeveloper);
    }

    Task<Reply> Merge(string path, object extra, string? token) =>
        _c.Post(path, MergeObjects(Finding, extra), token);

    static Dictionary<string, object?> MergeObjects(object a, object b)
    {
        var result = new Dictionary<string, object?>();
        foreach (var o in new[] { a, b })
            foreach (var p in o.GetType().GetProperties()) result[p.Name] = p.GetValue(o);
        return result;
    }

    async Task<Reply> FindingRow() => await _c.Get($"/api/findings?search={FindingCve}");

    // -- roles ---------------------------------------------------------------
    [Fact]
    public async Task Visitor_is_read_only()
    {
        var role = await _c.Get("/api/role");
        Assert.Equal("viewer", role.At("role").Text());
        Assert.False(role.At("write_enabled").Flag());
        Assert.False(role.At("can_dispute").Flag());
        Assert.False(role.At("can_set_pr").Flag());
    }

    [Fact]
    public async Task Automation_key_may_only_set_the_pr()
    {
        var role = await _c.Get("/api/role", Who.AutomationKey);
        Assert.Equal("automation", role.At("role").Text());
        Assert.True(role.At("can_set_pr").Flag());
        Assert.False(role.At("can_dispute").Flag());
        Assert.False(role.At("can_comment").Flag());
        Assert.False(role.At("write_enabled").Flag());

        var set = await Merge("/api/triage/google-pr", new { number = "#19015" }, Who.AutomationKey);
        Assert.Equal(200, set.Code);
        Assert.Equal("19015", set.At("triage.google_pr_number").Text());
        Assert.EndsWith("/pull/19015", set.At("triage.google_pr_url").Text());
        Assert.Equal(Cfg.AutomationIdentity, set.At("triage.google_pr_set_by").Text());

        Assert.Equal(401, (await Merge("/api/triage/comment", new { body = "hi" }, Who.AutomationKey)).Code);
        Assert.Equal(401, (await Merge("/api/triage/dispute", new { reason = "x" }, Who.AutomationKey)).Code);
        Assert.Equal(401, (await Merge("/api/triage/patch", new { final_verdict = "Patch Available" }, Who.AutomationKey)).Code);
        Assert.Equal(400, (await Merge("/api/triage/google-pr", new { number = "  " }, Who.AutomationKey)).Code);
    }

    [Fact]
    public async Task Guessing_a_key_gives_nothing_and_logout_revokes_a_session()
    {
        foreach (var guess in new[] { "akhila-dev5", "admin", "test-admin-key" })
            Assert.Equal("viewer", (await _c.Get("/api/role", guess)).At("role").Text());

        Assert.Equal("admin", (await _c.Get("/api/role", _admin)).At("role").Text());
        Assert.True((await _c.Post("/api/auth/logout", null, _admin)).At("signed_out").Flag());
        Assert.Equal("viewer", (await _c.Get("/api/role", _admin)).At("role").Text());
    }

    [Fact]
    public async Task Google_sign_in_is_unavailable_until_configured()
    {
        using var noRedirect = _f.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        Assert.Equal(503, (await noRedirect.Get("/api/auth/google")).Code);
    }

    [Fact]
    public async Task Developer_has_a_limited_set_of_capabilities()
    {
        var role = await _c.Get("/api/role", _dev);
        Assert.Equal("developer", role.At("role").Text());
        Assert.Equal(Who.Dev, role.At("identity.identity").Text());
        Assert.True(role.At("can_comment").Flag());
        Assert.True(role.At("can_dispute").Flag());
        Assert.True(role.At("can_set_pr").Flag());
        Assert.True(role.At("can_claim").Flag());
        Assert.False(role.At("can_assign").Flag());
        Assert.False(role.At("can_set_patch_verdict").Flag());
        Assert.False(role.At("can_approve_dispute").Flag());
        Assert.False(role.At("can_scan").Flag());
        Assert.False(role.At("write_enabled").Flag());

        var admin = await _c.Get("/api/role", _admin);
        Assert.True(admin.At("can_approve_dispute").Flag());
        Assert.True(admin.At("can_rescore").Flag());
    }

    [Fact]
    public async Task Visitors_cannot_write_anything()
    {
        Assert.Equal(401, (await Merge("/api/triage/comment", new { body = "hi" }, null)).Code);
        Assert.Equal(401, (await Merge("/api/triage/dispute", new { reason = "wrong" }, null)).Code);
        Assert.Equal(401, (await Merge("/api/triage/github-pr", new { number = "1" }, null)).Code);
        Assert.Equal(401, (await Merge("/api/triage/patch", new { final_verdict = "No Patch Found" }, null)).Code);
        Assert.Equal(401, (await Merge("/api/triage/claim", new { }, null)).Code);
        Assert.Equal(401, (await Merge("/api/triage/release", new { }, null)).Code);
        Assert.Equal(401, (await _c.Post("/api/scan", new { })).Code);
        Assert.Equal(401, (await _c.Post("/api/assignments", new { cve_id = FindingCve, package_name = "beta" })).Code);
        Assert.Equal(401, (await _c.Post("/api/disputes/1/approve")).Code);
        Assert.Equal(401, (await _c.Get("/api/workflows")).Code);
    }

    // -- admin triage --------------------------------------------------------
    [Fact]
    public async Task Admin_comments_and_disputes_and_the_trail_shows_both()
    {
        var comment = await Merge("/api/triage/comment", new { body = "Looking into this." }, _admin);
        Assert.Equal(200, comment.Code);
        Assert.Equal("comment", comment.At("comment.kind").Text());

        var dispute = await Merge("/api/triage/dispute", new { reason = "The distro backport covers this version." }, _admin);
        Assert.Equal(200, dispute.Code);
        Assert.Equal("dispute", dispute.At("comment.kind").Text());
        Assert.Equal("disputed", dispute.At("triage.triage_status").Text());

        var filtered = await _c.Get("/api/findings?branch=3.0&triage_status=disputed");
        Assert.Equal(1, filtered.At("total").Number());
        Assert.Equal(FindingCve, filtered.At("items.0.cve_id").Text());

        var history = await _c.Get($"/api/triage/comments?cve_id={FindingCve}&branch=3.0&spec_path=SPECS/beta/beta.spec");
        Assert.Equal("comment", history.At("items.0.kind").Text());
        Assert.Equal("dispute", history.At("items.1.kind").Text());
    }

    [Fact]
    public async Task Comments_and_disputes_need_content()
    {
        Assert.Equal(400, (await Merge("/api/triage/dispute", new { reason = "  " }, _admin)).Code);
        Assert.Equal(400, (await Merge("/api/triage/comment", new { body = "" }, _admin)).Code);
        Assert.Equal(400, (await _c.Post("/api/triage/comment", new { cve_id = "", body = "x" }, _admin)).Code);
    }

    [Fact]
    public async Task Admin_can_override_the_patch_verdict()
    {
        var resp = await Merge("/api/triage/patch", new
        {
            final_verdict = "Patch Available", patch_link = "https://example.com/fix.diff", available_since = "2026-09-30",
        }, _admin);
        Assert.Equal(200, resp.Code);
        var row = await FindingRow();
        Assert.Equal("Patch Available", row.At("items.0.triage.final_verdict").Text());
        Assert.Equal("Patch Available", row.At("items.0.patch_availability.final_verdict").Text());
        Assert.True(row.At("items.0.patch_availability.overridden").Flag());
    }

    [Fact]
    public async Task Github_pr_rejects_mismatched_or_external_urls()
    {
        Assert.Equal(400, (await Merge("/api/triage/github-pr", new { number = "12", url = "https://example.com/pull/12" }, _admin)).Code);
        Assert.Equal(400, (await Merge("/api/triage/github-pr", new { number = "12", url = "https://github.com/owner/repo/pull/13" }, _admin)).Code);
        var valid = await Merge("/api/triage/github-pr", new { number = "12", url = "https://github.com/owner/repo/pull/12" }, _admin);
        Assert.Equal(200, valid.Code);
        Assert.Equal("https://github.com/owner/repo/pull/12", valid.At("triage.github_pr_url").Text());
    }

    [Fact]
    public async Task Developer_can_comment_and_set_the_pr_but_not_do_admin_things()
    {
        var comment = await Merge("/api/triage/comment", new { body = "looking into it" }, _dev);
        Assert.Equal(200, comment.Code);
        Assert.Equal(Who.Dev, comment.At("comment.author").Text());

        var pr = await Merge("/api/triage/github-pr", new { number = "123" }, _dev);
        Assert.Equal(200, pr.Code);
        Assert.Equal(Who.Dev, pr.At("identity").Text());

        Assert.Equal(401, (await _c.Post("/api/assignments", new { cve_id = FindingCve, package_name = "beta" }, _dev)).Code);
        Assert.Equal(401, (await Merge("/api/triage/patch", new { final_verdict = "Patch Available" }, _dev)).Code);
        Assert.Equal(401, (await _c.Post("/api/scan", new { }, _dev)).Code);
        Assert.Equal(401, (await _c.Post($"/api/cves/{FindingCve}/rescore", new { severity = "low", reason = "x" }, _dev)).Code);

        var id = (await Merge("/api/triage/dispute", new { reason = "UPSTREAM: not affected" }, _dev)).At("dispute.id")!;
        Assert.Equal(401, (await _c.Post($"/api/disputes/{id}/approve", null, _dev)).Code);
        Assert.Equal(401, (await _c.Post($"/api/disputes/{id}/reject", null, _dev)).Code);
    }

    // -- disputes ------------------------------------------------------------
    [Fact]
    public async Task A_developer_dispute_waits_for_the_admin()
    {
        var resp = await Merge("/api/triage/dispute", new { reason = "UPSTREAM: not affected", first_unaffected_version = "1.2-3" }, _dev);
        Assert.Equal(200, resp.Code);
        Assert.False(resp.At("approved").Flag());
        Assert.Equal("pending", resp.At("dispute.status").Text());
        Assert.Equal(Who.Dev, resp.At("dispute.requested_by").Text());
        Assert.Equal("beta", resp.At("dispute.package_name").Text());
        Assert.Contains("First unaffected version: 1.2-3", resp.At("dispute.reason").Text());

        var row = await FindingRow();
        Assert.Equal("pending", row.At("items.0.dispute.status").Text());
        Assert.Empty(row.At("items.0.triage")?.AsObject() ?? new System.Text.Json.Nodes.JsonObject());
        var comments = await _c.Get($"/api/triage/comments?cve_id={FindingCve}&branch=3.0&spec_path=SPECS/beta/beta.spec");
        Assert.Equal(0, comments.At("items")!.AsArray().Count);
    }

    [Fact]
    public async Task Approval_marks_the_package_disputed_and_adds_the_reason()
    {
        var id = (await Merge("/api/triage/dispute", new { reason = "UPSTREAM: not affected" }, _dev)).At("dispute.id")!;
        var resp = await _c.Post($"/api/disputes/{id}/approve", new { note = "agreed" }, _admin);
        Assert.Equal(200, resp.Code);
        Assert.Equal("approved", resp.At("dispute.status").Text());

        var row = await FindingRow();
        Assert.Equal("disputed", row.At("items.0.triage.resolution_status").Text());
        Assert.Equal("disputed", row.At("items.0.triage.triage_status").Text());
        Assert.Equal("approved", row.At("items.0.dispute.status").Text());

        var comments = await _c.Get($"/api/triage/comments?cve_id={FindingCve}&branch=3.0&spec_path=SPECS/beta/beta.spec");
        Assert.Equal(1, comments.At("items")!.AsArray().Count);
        Assert.Equal("dispute", comments.At("items.0.kind").Text());
        Assert.Equal(Who.Dev, comments.At("items.0.author").Text());
        Assert.Contains("not affected", comments.At("items.0.body").Text());
    }

    [Fact]
    public async Task Rejection_leaves_the_package_alone_and_a_new_dispute_is_allowed()
    {
        var id = (await Merge("/api/triage/dispute", new { reason = "UPSTREAM: not affected" }, _dev)).At("dispute.id")!;
        var resp = await _c.Post($"/api/disputes/{id}/reject", new { note = "need evidence" }, _admin);
        Assert.Equal("rejected", resp.At("dispute.status").Text());
        Assert.Equal("need evidence", resp.At("dispute.decision_note").Text());
        Assert.Empty((await FindingRow()).At("items.0.triage")?.AsObject() ?? new System.Text.Json.Nodes.JsonObject());
        Assert.Equal(200, (await Merge("/api/triage/dispute", new { reason = "BACKPORT: fixed" }, _dev)).Code);
    }

    [Fact]
    public async Task Only_one_pending_dispute_per_package_and_each_is_decided_once()
    {
        var first = await Merge("/api/triage/dispute", new { reason = "UPSTREAM: not affected" }, _dev);
        var again = await Merge("/api/triage/dispute", new { reason = "OTHER: again" }, _dev);
        Assert.Equal(409, again.Code);
        Assert.Contains("already waiting", again.At("detail").Text());

        var id = first.At("dispute.id")!;
        Assert.Equal(200, (await _c.Post($"/api/disputes/{id}/approve", null, _admin)).Code);
        Assert.Equal(409, (await _c.Post($"/api/disputes/{id}/reject", null, _admin)).Code);
        Assert.Equal(404, (await _c.Post("/api/disputes/9999/approve", null, _admin)).Code);
    }

    [Fact]
    public async Task The_admins_own_dispute_is_approved_at_once_and_input_is_validated()
    {
        var own = await Merge("/api/triage/dispute", new { reason = "UPSTREAM: not affected" }, _admin);
        Assert.True(own.At("approved").Flag());
        Assert.Equal("approved", own.At("dispute.status").Text());
        Assert.Equal("disputed", (await FindingRow()).At("items.0.triage.resolution_status").Text());

        Assert.Equal(400, (await Merge("/api/triage/dispute", new { reason = "  " }, _dev)).Code);
        Assert.Equal(400, (await Merge("/api/triage/dispute", new { first_unaffected_version = "bad version!", reason = "x" }, _dev)).Code);
        var unknown = await _c.Post("/api/triage/dispute", new { cve_id = "CVE-1999-0001", reason = "x" }, _dev);
        Assert.Equal(404, unknown.Code);
    }

    [Fact]
    public async Task Disputes_list_filters_and_counts()
    {
        var id = (await Merge("/api/triage/dispute", new { reason = "UPSTREAM: not affected" }, _dev)).At("dispute.id")!;
        var all = await _c.Get("/api/disputes");
        Assert.Equal(1, all.At("total").Number());
        Assert.Equal(1, all.At("counts.pending").Number());
        Assert.Equal(0, (await _c.Get("/api/disputes?status=approved")).At("total").Number());

        await _c.Post($"/api/disputes/{id}/approve", null, _admin);
        var approved = await _c.Get("/api/disputes?status=approved");
        Assert.Equal(1, approved.At("total").Number());
        Assert.Equal(1, approved.At("counts.approved").Number());
        Assert.Equal(0, approved.At("counts.pending").Number());
        Assert.Equal(1, (await _c.Get("/api/disputes?search=beta")).At("total").Number());
        Assert.Equal(0, (await _c.Get("/api/disputes?search=zzz")).At("total").Number());
        Assert.Equal(400, (await _c.Get("/api/disputes?status=bogus")).Code);
    }

    // -- claims and workflows ------------------------------------------------
    [Fact]
    public async Task A_developer_claims_a_package_and_sees_it_in_workflows()
    {
        Assert.Equal(200, (await Merge("/api/triage/claim", new { }, _dev)).Code);
        Assert.Equal(Who.Dev, (await FindingRow()).At("items.0.triage.owner").Text());
        var mine = await _c.Get("/api/workflows", _dev);
        Assert.Equal(1, mine.At("total").Number());
        Assert.Equal(Who.Dev, mine.At("groups.0.owner").Text());
        Assert.Equal(FindingCve, mine.At("groups.0.items.0.cve_id").Text());
    }

    [Fact]
    public async Task Workflows_lists_me_first_then_everyone_else_alphabetically()
    {
        await Merge("/api/triage/claim", new { }, _dev);
        var seen = await _c.Get("/api/workflows", _other);
        Assert.Equal(1, seen.At("total").Number());
        Assert.Equal(Who.Other, seen.At("me").Text());
        Assert.Equal(Who.Other, seen.At("groups.0.owner").Text());
        Assert.Equal(Who.Dev, seen.At("groups.1.owner").Text());
        Assert.Equal(0, seen.At("groups.0.total").Number());
        Assert.Equal("claimed", seen.At("groups.1.items.0.held_via").Text());

        // the administrator's email sorts before "dev.*", yet the signed-in account still leads
        await Merge("/api/triage/release", new { }, _dev);
        await Merge("/api/triage/claim", new { }, _admin);
        var again = await _c.Get("/api/workflows", _dev);
        Assert.Equal(Who.Dev, again.At("groups.0.owner").Text());
        Assert.Equal(Cfg.AdminEmail, again.At("groups.1.owner").Text());
    }

    [Fact]
    public async Task Admin_assigned_packages_show_up_in_workflows()
    {
        var made = await _c.Post("/api/assignments",
            new { cve_id = FindingCve, package_name = "beta", assignee_email = Cfg.AdminEmail }, _admin);
        Assert.Equal(200, made.Code);
        var seen = await _c.Get("/api/workflows", _dev);
        var admin = seen.At("groups")!.AsArray().First(g => g.At("owner").Text() == Cfg.AdminEmail);
        Assert.Equal("assigned", admin.At("items.0.held_via").Text());
    }

    [Fact]
    public async Task A_claimed_package_cannot_be_taken_by_someone_else_but_the_admin_may_take_over()
    {
        await Merge("/api/triage/claim", new { }, _dev);
        var taken = await Merge("/api/triage/claim", new { }, _other);
        Assert.Equal(409, taken.Code);
        Assert.Contains(Who.Dev, taken.At("detail").Text());
        Assert.Equal(409, (await Merge("/api/triage/release", new { }, _other)).Code);

        Assert.Equal(200, (await Merge("/api/triage/claim", new { }, _dev)).Code);
        Assert.Equal(200, (await Merge("/api/triage/claim", new { }, _admin)).Code);
        Assert.Equal(Cfg.AdminEmail, (await FindingRow()).At("items.0.triage.owner").Text());
    }

    [Fact]
    public async Task Release_clears_the_owner()
    {
        await Merge("/api/triage/claim", new { }, _dev);
        Assert.Equal(200, (await Merge("/api/triage/release", new { }, _dev)).Code);
        Assert.Equal(0, (await _c.Get("/api/workflows", _dev)).At("total").Number());
        Assert.Equal("", (await FindingRow()).At("items.0.triage.owner").Text());
    }

    // -- rescoring -----------------------------------------------------------
    [Fact]
    public async Task Only_the_admin_can_rescore_and_input_is_validated()
    {
        var url = $"/api/cves/{FindingCve}/rescore";
        var body = new { severity = "critical", cvss_score = 9.1, reason = "Exploit published" };
        Assert.Equal(401, (await _c.Post(url, body)).Code);
        Assert.Equal(401, (await _c.Post(url, body, _dev)).Code);
        Assert.Equal(400, (await _c.Post(url, new { severity = "critical", cvss_score = 9.1, reason = "  " }, _admin)).Code);
        Assert.Equal(400, (await _c.Post(url, new { severity = "scary", cvss_score = 9.1, reason = "x" }, _admin)).Code);
        Assert.Equal(400, (await _c.Post(url, new { severity = "critical", cvss_score = 11, reason = "x" }, _admin)).Code);
        Assert.Equal(404, (await _c.Post("/api/cves/CVE-1999-0001/rescore", body, _admin)).Code);
    }

    [Fact]
    public async Task Rescoring_changes_severity_and_score_everywhere_and_keeps_the_scanned_values()
    {
        var before = await FindingRow();
        var originalSeverity = before.At("items.0.severity").Text();
        var originalScore = before.At("items.0.cvss_score").Number();
        var criticalBefore = (await _c.Get("/api/findings?severity=critical")).At("total").Number();

        var done = await _c.Post($"/api/cves/{FindingCve}/rescore",
            new { severity = "critical", cvss_score = 9.1, reason = "Exploit published" }, _admin);
        Assert.Equal(200, done.Code);

        var row = await FindingRow();
        Assert.Equal("critical", row.At("items.0.severity").Text());
        Assert.Equal(9.1, row.At("items.0.cvss_score").Number());
        Assert.Equal(originalSeverity, row.At("items.0.scanned_severity").Text());
        Assert.Equal(originalScore, row.At("items.0.scanned_cvss_score").Number());
        Assert.Equal("Exploit published", row.At("items.0.rescore.reason").Text());

        Assert.Equal(criticalBefore + 1, (await _c.Get("/api/findings?severity=critical")).At("total").Number());

        // rescoring again keeps the first scanned values
        await _c.Post($"/api/cves/{FindingCve}/rescore", new { severity = "low", cvss_score = 3.1, reason = "Fixed in config" }, _admin);
        var again = await FindingRow();
        Assert.Equal("low", again.At("items.0.severity").Text());
        Assert.Equal(originalSeverity, again.At("items.0.scanned_severity").Text());
    }
}
