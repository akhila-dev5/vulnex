using Xunit;

namespace Vulnex.Api.Tests;

/// <summary>
/// The Automation section and the worker's job endpoints. Ported from the old Python tests
/// (test_automation and the API half of test_automation_engine).
/// </summary>
[Collection("database")]
[Trait("Suite", "Workflow")]
public class AutomationTests
{
    const string FindingCve = "CVE-2024-0002";
    static readonly object Finding = new { cve_id = FindingCve, branch = "3.0", spec_path = "SPECS/beta/beta.spec" };
    static readonly string Automation = Cfg.AutomationEmail;

    readonly HttpClient _c;
    readonly string _admin;
    readonly string _dev;

    public AutomationTests(ApiFactory factory)
    {
        factory.ResetTriage();
        _c = factory.CreateClient();
        _admin = factory.AdminToken();
        _dev = factory.Token(Who.Dev, Cfg.RoleDeveloper);
    }

    static Dictionary<string, object?> Package(params (string, object?)[] extra)
    {
        var d = new Dictionary<string, object?>
        {
            ["package_name"] = "beta", ["branch"] = "3.0", ["spec_path"] = "SPECS/beta/beta.spec",
        };
        foreach (var (k, v) in extra) d[k] = v;
        return d;
    }

    Task<Reply> Triage(string path, object extra, string token)
    {
        var body = new Dictionary<string, object?> { ["cve_id"] = FindingCve, ["branch"] = "3.0", ["spec_path"] = "SPECS/beta/beta.spec" };
        foreach (var p in extra.GetType().GetProperties()) body[p.Name] = p.GetValue(extra);
        return _c.Post(path, body, token);
    }

    async Task AssignToAutomation(string verdict = "Patch Available", string patchLink = "")
    {
        await _c.Post("/api/assignments", new { cve_id = FindingCve, package_name = "beta", assignee_email = Automation }, _admin);
        if (verdict.Length > 0)
            await Triage("/api/triage/patch", new { final_verdict = verdict, patch_link = patchLink }, _admin);
    }

    [Fact]
    public async Task Visitors_are_refused()
    {
        Assert.Equal(401, (await _c.Get("/api/automation")).Code);
        var body = Package(("cve_ids", new[] { FindingCve }), ("mode", "new_pr"));
        Assert.Equal(401, (await _c.Post("/api/automation/requests", body)).Code);
    }

    [Fact]
    public async Task Only_the_automation_accounts_patch_available_cves_are_listed()
    {
        Assert.Equal(0, (await _c.Get("/api/automation", _dev)).At("packages")!.AsArray().Count);

        await AssignToAutomation("No Patch Found"); // assigned, but the verdict says no patch
        var none = await _c.Get("/api/automation", _dev);
        Assert.Equal(0, none.At("packages")!.AsArray().Count);

        await AssignToAutomation();
        var body = await _c.Get("/api/automation", _dev);
        Assert.Equal(Automation, body.At("owner").Text());
        Assert.Equal(1, body.At("total").Number());
        Assert.Equal("beta", body.At("packages.0.package_name").Text());
        Assert.Equal(FindingCve, body.At("packages.0.items.0.cve_id").Text());
    }

    [Fact]
    public async Task Someone_elses_package_is_not_listed()
    {
        await _c.Post("/api/assignments", new { cve_id = FindingCve, package_name = "beta", assignee_email = "dev1.vulnex@gmail.com" }, _admin);
        await Triage("/api/triage/patch", new { final_verdict = "Patch Available" }, _admin);
        Assert.Equal(0, (await _c.Get("/api/automation", _dev)).At("packages")!.AsArray().Count);
    }

    [Fact]
    public async Task A_new_pr_request_is_queued()
    {
        await AssignToAutomation();
        var made = await _c.Post("/api/automation/requests", Package(("cve_ids", new[] { FindingCve }), ("mode", "new_pr")), _dev);
        Assert.Equal(200, made.Code);
        Assert.Equal("queued", made.At("request.status").Text());
        Assert.Equal("new_pr", made.At("request.mode").Text());
        Assert.Equal("", made.At("request.pr_number").Text());
        Assert.Equal(FindingCve, made.At("request.cve_ids.0").Text());

        var shown = await _c.Get("/api/automation", _dev);
        Assert.Equal(made.At("request.id")!.ToJsonString(), shown.At("packages.0.requests.0.id")!.ToJsonString());
    }

    [Fact]
    public async Task An_existing_pr_needs_a_numeric_pr_number()
    {
        await AssignToAutomation();
        Assert.Equal(400, (await _c.Post("/api/automation/requests", Package(("cve_ids", new[] { FindingCve }), ("mode", "existing_pr")), _dev)).Code);
        Assert.Equal(400, (await _c.Post("/api/automation/requests", Package(("cve_ids", new[] { FindingCve }), ("mode", "existing_pr"), ("pr_number", "abc")), _dev)).Code);
        var ok = await _c.Post("/api/automation/requests", Package(("cve_ids", new[] { FindingCve }), ("mode", "existing_pr"), ("pr_number", "#123")), _dev);
        Assert.Equal(200, ok.Code);
        Assert.Equal("123", ok.At("request.pr_number").Text());
    }

    [Fact]
    public async Task Empty_unknown_and_bad_mode_are_rejected()
    {
        await AssignToAutomation();
        Assert.Equal(400, (await _c.Post("/api/automation/requests", Package(("cve_ids", Array.Empty<string>()), ("mode", "new_pr")), _dev)).Code);
        Assert.Equal(400, (await _c.Post("/api/automation/requests", Package(("cve_ids", new[] { "CVE-1999-0001" }), ("mode", "new_pr")), _dev)).Code);
        Assert.Equal(400, (await _c.Post("/api/automation/requests", Package(("cve_ids", new[] { FindingCve }), ("mode", "both")), _dev)).Code);
    }

    [Fact]
    public async Task Worker_endpoints_need_the_automation_key()
    {
        Assert.Equal(401, (await _c.Post("/api/automation/jobs/next")).Code);
        Assert.Equal(401, (await _c.Post("/api/automation/jobs/next", null, _admin)).Code);
        var none = await _c.Post("/api/automation/jobs/next", null, Who.AutomationKey);
        Assert.Equal(200, none.Code);
        Assert.Equal("null", none.At("job")?.ToJsonString() ?? "null");
    }

    [Fact]
    public async Task A_queued_request_becomes_a_job_and_its_result_is_recorded()
    {
        const string link = "https://github.com/o/r/commit/abcdef1";
        await AssignToAutomation("Patch Available", link);
        var body = Package(("cve_ids", new[] { FindingCve }), ("mode", "new_pr"));
        Assert.Equal(200, (await _c.Post("/api/automation/requests", body, _admin)).Code);
        // while it waits, the package cannot be queued twice
        Assert.Equal(409, (await _c.Post("/api/automation/requests", body, _admin)).Code);

        var next = await _c.Post("/api/automation/jobs/next", null, Who.AutomationKey);
        Assert.Equal("beta", next.At("job.package_name").Text());
        Assert.Equal(FindingCve, next.At("job.cves.0.cve_id").Text());
        Assert.Equal(link, next.At("job.cves.0.patch_link").Text());
        var taken = await _c.Post("/api/automation/jobs/next", null, Who.AutomationKey);
        Assert.Equal("null", taken.At("job")?.ToJsonString() ?? "null");

        var id = next.At("job.id")!.ToJsonString();
        var done = await _c.Post($"/api/automation/jobs/{id}/result", new
        {
            status = "done", pr_url = "https://github.com/akhila-dev5/azurelinux-test/pull/9", pr_number = "9",
            branch_name = "topic/beta/3.0/x",
        }, Who.AutomationKey);
        Assert.Equal("done", done.At("request.status").Text());
        Assert.EndsWith("/pull/9", done.At("request.pr_url").Text());

        // once the PR is set on the CVE, it leaves the Automation list
        await Triage("/api/triage/github-pr", new { number = "9", url = "https://github.com/akhila-dev5/azurelinux-test/pull/9" }, Who.AutomationKey);
        Assert.Equal(0, (await _c.Get("/api/automation", _admin)).At("packages")!.AsArray().Count);
    }
}
