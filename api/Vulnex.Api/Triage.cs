using System.Text.RegularExpressions;

namespace Vulnex.Api;

/// <summary>
/// Reading-side triage helpers (port of triage.py): tracker links, the "Patch
/// Available" verdict, and the Deep view. Pure functions over snapshot data.
/// </summary>
public static class Triage
{
    static readonly Regex PatchUrl = new(@"(/commit/|/pull/|\.diff($|\?)|\.patch($|\?)|patch-diff)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    static readonly (string Label, string Template)[] Trackers =
    {
        ("Ubuntu", "https://ubuntu.com/security/{cve}"),
        ("Debian", "https://security-tracker.debian.org/tracker/{cve}"),
        ("Red Hat", "https://access.redhat.com/security/cve/{cve}"),
        ("Mitre", "https://www.cve.org/CVERecord?id={cve}"),
        ("OSV", "https://osv.dev/vulnerability/{cve}"),
        ("NVD", "https://nvd.nist.gov/vuln/detail/{cve}"),
    };

    public static List<Row> WebsiteLinks(string? cveId)
    {
        var cve = (cveId ?? "").ToUpperInvariant();
        if (cve.Length == 0) return new();
        return Trackers.Select(t => new Row { ["label"] = t.Label, ["url"] = t.Template.Replace("{cve}", cve) }).ToList();
    }

    static string RepoBlob(string specPath, string branch, string filename)
    {
        if (specPath.Length == 0 || filename.Length == 0) return "";
        var slash = specPath.LastIndexOf('/');
        var directory = slash >= 0 ? specPath[..slash] : "";
        var path = string.Join("/", new[] { directory, filename }.Where(p => p.Length > 0));
        return $"https://github.com/{Cfg.RepoOwner}/{Cfg.RepoName}/blob/{branch}/{path}";
    }

    static List<object?> AsList(object? v) => v as List<object?> ?? new();

    static List<string> CandidatePatchLinks(Row finding, Row? enrichment)
    {
        var urls = new List<string>();
        var seen = new HashSet<string>();
        void Add(object? url)
        {
            if (url is not string s || s.Length == 0 || seen.Contains(s)) return;
            if (PatchUrl.IsMatch(s)) { seen.Add(s); urls.Add(s); }
        }
        var upstream = finding.Str("upstream_fix");
        if (upstream.Length > 0) Add(upstream);
        var references = enrichment is not null && AsList(enrichment.Get("references")).Count > 0
            ? AsList(enrichment.Get("references"))
            : AsList(finding.Get("references"));
        foreach (var r in references)
            if (r is Row rr) Add(rr.Get("url"));
        return urls;
    }

    public static Row PatchAvailability(Row finding, Row? enrichment = null, Row? triage = null)
    {
        var status = finding.Str("status");
        triage ??= new Row();
        var applicable = status == "affected";

        var candidates = CandidatePatchLinks(finding, enrichment);
        var upstreamFix = finding.Str("upstream_fix");

        string patchLink, source;
        if (upstreamFix.Length > 0) { patchLink = upstreamFix; source = "upstream-fix"; }
        else if (candidates.Count > 0) { patchLink = candidates[0]; source = "upstream-reference"; }
        else { patchLink = ""; source = "none"; }

        var available = patchLink.Length > 0;
        var aiVerdict = !applicable ? "Not applicable" : (available ? "Patch Available" : "No Patch Found");

        var published = enrichment?.Str("published") ?? "";
        if (published.Length == 0) published = finding.Str("advisory_published");
        var availableSince = published.Length > 0 && available ? published[..Math.Min(10, published.Length)] : "";

        var finalVerdict = triage.Str("final_verdict");
        if (finalVerdict.Length == 0) finalVerdict = aiVerdict;
        var overrideLink = triage.Str("patch_link");
        var overrideSince = triage.Str("available_since");

        var analysis = new List<string>();
        if (!applicable)
            analysis.Add($"Finding is '{(status.Length > 0 ? status : "unknown")}', not an open exposure — patch availability does not apply.");
        if (upstreamFix.Length > 0) analysis.Add($"Upstream fix commit: {upstreamFix}");
        foreach (var url in candidates.Take(3))
            if (url != upstreamFix) analysis.Add($"Upstream advisory reference looks patchable: {url}");
        if (finding.Str("fixed_version").Length > 0)
        {
            var br = finding.Str("branch");
            analysis.Add($"Upstream fixed version {finding.Str("fixed_version")} is not yet shipped on {(br.Length > 0 ? br : "this branch")}.");
        }
        if (analysis.Count == 0)
            analysis.Add("No upstream fix commit or patchable upstream reference was found for this CVE.");

        return new Row
        {
            ["applicable"] = applicable,
            ["available"] = available,
            ["ai_verdict"] = aiVerdict,
            ["final_verdict"] = finalVerdict,
            ["overridden"] = triage.Str("final_verdict").Length > 0,
            ["possible_links"] = candidates,
            ["patch_link"] = overrideLink.Length > 0 ? overrideLink : patchLink,
            ["available_since"] = overrideSince.Length > 0 ? overrideSince : availableSince,
            ["source"] = source,
            ["analysis"] = analysis,
        };
    }

    public static Row DeepView(Row finding, Row? package = null)
    {
        package ??= new Row();
        var branch = finding.Str("branch");
        var specPath = finding.Str("spec_path");
        var affected = AsList(finding.Get("affected_files"));
        var patchName = finding.Str("patch_name");

        var backports = new List<Row>();
        if (patchName.Length > 0 && !patchName.EndsWith(".nopatch"))
            backports.Add(new Row
            {
                ["filename"] = patchName,
                ["url"] = RepoBlob(specPath, branch, patchName),
                ["present"] = finding.Get("patch_file_present"),
            });

        Row? tarball = null;
        if (package.Str("tarball_name").Length > 0)
            tarball = new Row
            {
                ["name"] = package.Get("tarball_name"),
                ["url"] = package.Str("tarball_url"),
                ["available"] = package.Get("tarball_available"),
            };

        var notes = new List<string>
        {
            affected.Count > 0
                ? "Files listed are the paths touched by the upstream fix commit for this CVE."
                : "No upstream fix commit was resolvable, so the touched files could not be listed from that source.",
            tarball is not null
                ? $"Source tarball for this package: {tarball.Str("name")}."
                : "This package declares no source tarball in its .spec file.",
        };

        var specUrl = package.Str("spec_url");
        if (specUrl.Length == 0) specUrl = finding.Str("spec_url");

        return new Row
        {
            ["cve_id"] = finding.Get("cve_id"),
            ["package_name"] = finding.Get("package_name"),
            ["package_version"] = finding.Get("package_version"),
            ["branch"] = branch,
            ["spec_path"] = specPath,
            ["spec_url"] = specUrl,
            ["tarball"] = tarball,
            ["upstream_fixed_version"] = finding.Str("fixed_version"),
            ["affected_files"] = affected,
            ["backport_patches"] = backports,
            ["notes"] = notes,
        };
    }

    public static (string? Version, string? Basis) AzlFixedVersion(Row finding)
    {
        if (finding.Str("status") != "patched") return (null, null);
        var v = finding.Str("fixed_in");
        var b = finding.Str("fixed_in_basis");
        return (v.Length > 0 ? v : null, b.Length > 0 ? b : null);
    }

    public static Row DecorateFinding(Row finding, Row? package = null, Row? enrichment = null,
        bool includeLinks = true, bool includeDeep = true)
    {
        if (includeLinks) finding["links"] = WebsiteLinks(finding.Str("cve_id"));
        var (v, b) = AzlFixedVersion(finding);
        finding["azl_fixed_version"] = v;
        finding["azl_fixed_basis"] = b;
        finding["patch_availability"] = PatchAvailability(finding, enrichment, finding.Sub("triage"));
        if (includeDeep) finding["deep"] = DeepView(finding, package);
        return finding;
    }
}
