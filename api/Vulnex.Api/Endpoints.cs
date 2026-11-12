using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Vulnex.Api;

/// <summary>
/// All HTTP endpoints. Paths, query parameters, status codes and JSON shapes match the
/// Python FastAPI backend one-to-one, so the React app and the automation worker need no change.
/// </summary>
public static class Endpoints
{
    // -- small helpers ---------------------------------------------------------
    static IResult Ok(object? value) => Results.Json(value, Json.Options);
    static IResult Status(int code, object? value) => Results.Json(value, Json.Options, statusCode: code);

    static async Task<T> Body<T>(HttpRequest req) where T : class
    {
        try
        {
            var value = await req.ReadFromJsonAsync<T>(Json.Options);
            if (value is not null) return value;
        }
        catch (JsonException) { /* fall through to 422 */ }
        catch (InvalidOperationException) { /* wrong content type */ }
        throw new HttpError(422, "The request body is missing or invalid.");
    }

    static async Task<T?> OptionalBody<T>(HttpRequest req) where T : class
    {
        using var reader = new StreamReader(req.Body);
        var text = await reader.ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(text)) return null;
        try { return JsonSerializer.Deserialize<T>(text, Json.Options); }
        catch (JsonException) { throw new HttpError(422, "The request body is invalid."); }
    }

    static void CheckLimit(int limit, int max)
    {
        if (limit < 1 || limit > max) throw new HttpError(422, $"limit must be between 1 and {max}.");
    }

    static List<string>? BranchesForFilter(string branch) => branch switch
    {
        "3.0" => new List<string> { "3.0" },
        "4.0" => new List<string> { "4.0" },
        _ => null,
    };

    static string Key(params object?[] parts) =>
        string.Join("\u001f", parts.Select(p => Convert.ToString(p, CultureInfo.InvariantCulture) ?? ""));

    static bool IsDigits(string s) => s.Length > 0 && s.All(ch => ch is >= '0' and <= '9');

    static string Trimmed(string? s) => (s ?? "").Trim();

    // -- decoration ------------------------------------------------------------
    /// <summary>Attach triage state, patch availability, links and the Deep view.</summary>
    static void DecorateFindings(DbConnection conn, List<Row> findings, Row? package = null, Row? enrichment = null, bool slim = false)
    {
        var assignments = new Dictionary<(string, string), Row>();
        foreach (var item in Repo.ListAssignments(conn)) assignments[(item.Str("cve_id"), item.Str("package_name"))] = item;
        var records = Repo.TriageIndex(conn);
        var disputes = Repo.DisputeIndex(conn);
        foreach (var finding in findings)
        {
            var key = FindingKey.Of(finding);
            finding["triage"] = records.GetValueOrDefault(key);
            finding["assignment"] = assignments.GetValueOrDefault((finding.Str("cve_id"), finding.Str("package_name")));
            finding["dispute"] = disputes.GetValueOrDefault(key);
            Triage.DecorateFinding(finding, package, enrichment, includeLinks: !slim, includeDeep: !slim);
            if (slim) finding.Remove("raw_sources");
        }
    }

    static Row? PackageFor(DbConnection conn, Row finding) =>
        Repo.GetPackage(conn, finding.Str("package_name"), finding.Get("branch") as string, finding.Get("spec_path") as string);

    static bool OlderThanADay(string? stamp)
    {
        if (!DateTimeOffset.TryParse(stamp ?? "", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var then)) return true;
        return (DateTimeOffset.UtcNow - then).TotalSeconds > 86400;
    }

    // -- automation ------------------------------------------------------------
    static List<Row> AutomationPackages(DbConnection conn)
    {
        var me = Cfg.AutomationEmail.Trim().ToLowerInvariant();
        var (rows, _) = Repo.ListFindings(conn, new Repo.FindingFilter(), 1_000_000, 0);
        DecorateFindings(conn, rows, slim: true);
        var groups = new Dictionary<(string, string, string), Row>();
        var order = new List<(string, string, string)>();
        foreach (var row in rows)
        {
            var assigned = (row.Sub("assignment")?.Str("assignee_email") ?? "").Trim().ToLowerInvariant();
            var claimed = (row.Sub("triage")?.Str("owner") ?? "").Trim().ToLowerInvariant();
            var owner = assigned.Length > 0 ? assigned : claimed;
            if (owner != me || row.Str("status") != "affected") continue;
            if ((row.Sub("patch_availability")?.Str("final_verdict") ?? "") != "Patch Available") continue;
            if ((row.Sub("triage")?.Str("github_pr_number") ?? "").Trim().Length > 0) continue;
            var key = (row.Str("package_name"), row.Str("branch"), row.Str("spec_path"));
            if (!groups.TryGetValue(key, out var group))
            {
                groups[key] = group = new Row
                {
                    ["package_name"] = key.Item1, ["package_version"] = row.Get("package_version"),
                    ["branch"] = key.Item2, ["spec_path"] = key.Item3,
                    ["items"] = new List<Row>(), ["requests"] = new List<Row>(),
                };
                order.Add(key);
            }
            ((List<Row>)group["items"]!).Add(row);
        }
        var requests = Repo.ListAutomationRequests(conn);
        foreach (var group in groups.Values)
        {
            var items = (List<Row>)group["items"]!;
            items.Sort((a, b) => string.CompareOrdinal(a.Str("cve_id"), b.Str("cve_id")));
            var k = (group.Str("package_name"), group.Str("branch"), group.Str("spec_path"));
            bool Same(Row r) => (r.Str("package_name"), r.Str("branch"), r.Str("spec_path")) == k;
            group["busy"] = requests.Any(r => (r.Str("status") is "queued" or "running") && Same(r));
            group["requests"] = requests.Where(Same).Take(3).ToList();
        }
        return groups.Values
            .OrderBy(g => g.Str("package_name").ToLowerInvariant(), StringComparer.Ordinal)
            .ThenBy(g => g.Str("branch"), StringComparer.Ordinal)
            .ToList();
    }

    static async Task DispatchRunnerAsync(HttpClient http)
    {
        if (Cfg.DispatchToken.Length == 0) return;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var req = new HttpRequestMessage(HttpMethod.Post,
                $"https://api.github.com/repos/{Cfg.DispatchRepo}/actions/workflows/automation.yml/dispatches")
            {
                Content = new StringContent("{\"ref\":\"main\"}", System.Text.Encoding.UTF8, "application/json"),
            };
            req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", Cfg.DispatchToken);
            req.Headers.Accept.ParseAdd("application/vnd.github+json");
            req.Headers.UserAgent.ParseAdd("vulnex-api");
            using var response = await http.SendAsync(req, cts.Token);
        }
        catch
        {
            // the schedule is the fallback; never fail the request over this
        }
    }

    static Row ApplyApprovedDispute(DbConnection conn, Row dispute)
    {
        var comment = Repo.AddFindingComment(conn, dispute.Str("cve_id"), dispute.Str("branch"), dispute.Str("spec_path"),
            dispute.Str("reason"), dispute.Str("requested_by").Length > 0 ? dispute.Str("requested_by") : "developer", "dispute");
        var record = Repo.UpsertTriage(conn, dispute.Str("cve_id"), dispute.Str("branch"), dispute.Str("spec_path"),
            new Dictionary<string, object?>
            {
                ["triage_status"] = "disputed", ["resolution_status"] = "disputed", ["package_name"] = dispute.Str("package_name"),
            });
        return new Row { ["comment"] = comment, ["triage"] = record };
    }

    static Row Merge(Row a, Row? b)
    {
        var merged = new Row(a);
        if (b is not null) foreach (var kv in b) merged[kv.Key] = kv.Value;
        return merged;
    }

    // -- mapping ---------------------------------------------------------------
    public static void Map(WebApplication app)
    {
        // ---- health, role, auth ----
        app.MapGet("/api/health", async (IDbFactory db) =>
        {
            var body = new Row { ["status"] = "ok", ["version"] = Cfg.Version, ["time"] = Sql.UtcNow() };
            if (Cfg.DatabaseUrl.Length == 0)
                return Status(503, Merge(body, new Row { ["status"] = "unavailable", ["database"] = "unreachable", ["detail"] = "DATABASE_URL is not set." }));
            try
            {
                using var conn = db.Open();
                Sql.Count(conn, "SELECT 1");
            }
            catch (DatabaseUnavailable ex)
            {
                return Status(503, Merge(body, new Row { ["status"] = "unavailable", ["database"] = "unreachable", ["detail"] = ex.Message }));
            }
            await Task.CompletedTask;
            body["database"] = "postgres";
            return Ok(body);
        });

        app.MapGet("/api/role", (HttpRequest req, AuthService auth) =>
        {
            var role = auth.ResolveRole(req);
            var session = auth.Sessions.Get(AuthService.Credential(req));
            var identity = Cfg.IdentityFor(role);
            var email = session?.Identity.GetValueOrDefault("email") as string ?? identity.Str("email");
            var result = new Row
            {
                ["role"] = role,
                ["identity"] = Merge(identity, new Row { ["identity"] = auth.ActorIdentity(req, role), ["email"] = email }),
                ["methods"] = new Row { ["google"] = Cfg.GoogleLoginConfigured, ["google_email"] = Cfg.AdminEmailAllowlist },
                ["expires_at"] = session?.ExpiresAt,
            };
            foreach (var kv in Roles.CapabilityFlags(role)) result[kv.Key] = kv.Value;
            return Ok(result);
        });

        app.MapPost("/api/auth/logout", (HttpRequest req, AuthService auth) =>
            Ok(new Row { ["signed_out"] = auth.Sessions.Drop(AuthService.Credential(req)) }));

        static string CallbackUrl(HttpRequest req) =>
            Cfg.GoogleRedirect.Length > 0 ? Cfg.GoogleRedirect : $"{req.Scheme}://{req.Host}/api/auth/google/callback";

        app.MapGet("/api/auth/google", (HttpRequest req, AuthService auth) =>
        {
            if (!Cfg.GoogleLoginConfigured) throw new HttpError(503, "Google sign-in is not configured.");
            var state = auth.States.New();
            return Results.Redirect(AuthService.AuthorizeUrl(CallbackUrl(req), state), permanent: false, preserveMethod: true);
        });

        app.MapGet("/api/auth/google/callback", async (HttpRequest req, AuthService auth, string? code, string? state) =>
        {
            if (!Cfg.GoogleLoginConfigured) throw new HttpError(503, "Google sign-in is not configured.");
            if (!auth.States.Consume(state)) throw new HttpError(400, "The Google sign-in link expired. Please try again.");
            var user = await auth.ExchangeAsync(code ?? "", CallbackUrl(req));
            string? email = null;
            var verified = false;
            if (user is { } u)
            {
                if (u.TryGetProperty("email", out var e) && e.ValueKind == JsonValueKind.String) email = e.GetString();
                verified = u.TryGetProperty("email_verified", out var v) && v.ValueKind == JsonValueKind.True;
            }
            var role = Roles.GoogleRoleFor(email, verified);
            if (role is null)
                throw new HttpError(403, "This Google account is not allowed to sign in. Ask the administrator to add it.");
            var identity = Merge(Cfg.IdentityFor(role), new Row { ["identity"] = email, ["email"] = email });
            var (token, _) = auth.Sessions.Create(identity, "google", role);
            return Results.Redirect($"/#vulnex_token={token}", permanent: false, preserveMethod: true);
        });

        // ---- read endpoints ----
        app.MapGet("/api/stats", (IDbFactory db, ResponseCache cache, string? branch) =>
        {
            branch ??= "";
            if (branch.Length > 0 && BranchesForFilter(branch) is null)
                throw new HttpError(400, "Choose stable branch 3.0 or 4.0.");
            var data = cache.Cached(Key("stats", branch), () =>
            {
                using var conn = db.Open();
                var stats = Repo.Stats(conn, branch.Length > 0 ? branch : null);
                stats["repository"] = Cfg.RepositoryMetadata();
                stats["roles"] = Cfg.RolesMetadata();
                stats["selected_branch"] = branch.Length > 0 ? branch : null;
                return stats;
            });
            return Ok(data);
        });

        app.MapGet("/api/packages", (IDbFactory db, string? search, string? branch, int page = 1, int limit = 50) =>
        {
            CheckLimit(limit, 500);
            branch ??= "";
            var branches = BranchesForFilter(branch);
            using var conn = db.Open();
            var (rows, total) = Repo.ListPackages(conn, search ?? "", branches is null ? branch : "", limit, (Math.Max(page, 1) - 1) * limit, branches);
            return Ok(new Row { ["items"] = rows, ["total"] = total, ["page"] = page, ["limit"] = limit });
        });

        app.MapGet("/api/packages/{name}", (IDbFactory db, string name, string? branch, string? spec) =>
        {
            using var conn = db.Open();
            var pkg = Repo.GetPackage(conn, name, branch, spec);
            if (pkg is null) throw new HttpError(404, "Package not found");
            DecorateFindings(conn, (List<Row>)pkg["findings"]!, package: pkg);
            return Ok(pkg);
        });

        app.MapGet("/api/findings", (IDbFactory db, ResponseCache cache, string? severity, string? status, string? search, string? package,
            string? branch, string? patch_state, string? triage_status, string? resolution_status, string? owner,
            string? fixed_version, int page = 1, int limit = 100) =>
        {
            CheckLimit(limit, 1000);
            severity ??= ""; status ??= ""; search ??= ""; package ??= ""; branch ??= ""; patch_state ??= "";
            triage_status ??= ""; resolution_status ??= ""; owner ??= ""; fixed_version ??= "";
            var key = Key("findings", severity, status, search, package, branch, page, limit, patch_state,
                triage_status, resolution_status, owner, fixed_version);
            var result = cache.Cached(key, () =>
            {
                var branches = BranchesForFilter(branch);
                var filter = new Repo.FindingFilter
                {
                    Status = status, Severity = severity, Search = search, Package = package,
                    Branch = branches is null ? branch : "", Branches = branches,
                    TriageStatus = triage_status, ResolutionStatus = resolution_status,
                    Owner = owner, FixedVersion = fixed_version,
                };
                using var conn = db.Open();
                if (patch_state.Length == 0)
                {
                    var (rows, total) = Repo.ListFindings(conn, filter, limit, (Math.Max(page, 1) - 1) * limit);
                    DecorateFindings(conn, rows, slim: true);
                    return new Row { ["items"] = rows, ["total"] = total, ["page"] = page, ["limit"] = limit };
                }
                var (all, _) = Repo.ListFindings(conn, filter, 1_000_000, 0);
                DecorateFindings(conn, all, slim: true);
                var want = patch_state == "available";
                var filtered = patch_state is "available" or "unavailable"
                    ? all.Where(f => ((f.Sub("patch_availability")?.Get("available") as bool?) ?? false) == want).ToList()
                    : all;
                var start = Math.Max(page - 1, 0) * limit;
                return new Row
                {
                    ["items"] = filtered.Skip(start).Take(limit).ToList(),
                    ["total"] = filtered.Count, ["page"] = page, ["limit"] = limit,
                };
            });
            return Ok(result);
        });

        app.MapGet("/api/cves/{cve_id}", async (IDbFactory db, Engine engine, string cve_id, bool enrich = true) =>
        {
            var cveId = cve_id.ToUpperInvariant();
            List<Row> findings;
            Row? cached;
            Row? assignment = null;
            using (var conn = db.Open())
            {
                findings = Repo.FindingsForCve(conn, cveId);
                cached = Repo.GetCachedCve(conn, cveId);
                assignment = Repo.ListAssignments(conn).FirstOrDefault(a => a.Str("cve_id") == cveId);
            }
            if (findings.Count == 0) throw new HttpError(404, "CVE not found in the current scan");

            var enrichment = cached;
            if (enrich && cached is not null && cached.Get("cvss_score") is null && OlderThanADay(cached.Str("_fetched_at")))
                enrichment = null; // no score last time; the sources may have one by now
            if (enrich && enrichment is null)
            {
                try
                {
                    enrichment = await engine.RunJsonAsync("enrich", cveId) as Row;
                    if (enrichment is not null)
                    {
                        using var conn = db.Open();
                        Repo.CacheCve(conn, cveId, enrichment);
                    }
                }
                catch
                {
                    enrichment = cached; // network failures are non-fatal
                }
            }

            using (var conn = db.Open())
            {
                var disputes = Repo.DisputeIndex(conn);
                foreach (var finding in findings)
                {
                    finding["dispute"] = disputes.GetValueOrDefault(FindingKey.Of(finding));
                    finding["triage"] = Repo.GetTriage(conn, finding.Str("cve_id"), finding.Str("branch"), finding.Str("spec_path"));
                    Triage.DecorateFinding(finding, PackageFor(conn, finding), enrichment);
                }
            }
            return Ok(new Row
            {
                ["cve_id"] = cveId, ["findings"] = findings, ["enrichment"] = enrichment,
                ["assignment"] = assignment, ["links"] = Triage.WebsiteLinks(cveId),
            });
        });

        app.MapGet("/api/cves/{cve_id}/deep", (IDbFactory db, string cve_id, string? branch, string? spec) =>
        {
            var cveId = cve_id.ToUpperInvariant();
            using var conn = db.Open();
            var results = Repo.FindingsForCve(conn, cveId);
            if (!string.IsNullOrEmpty(branch)) results = results.Where(f => f.Str("branch") == branch).ToList();
            if (!string.IsNullOrEmpty(spec)) results = results.Where(f => f.Str("spec_path") == spec).ToList();
            var finding = results.FirstOrDefault();
            if (finding is null) throw new HttpError(404, "CVE/package/branch combination not found in the current scan");
            return Ok(Triage.DeepView(finding, PackageFor(conn, finding)));
        });

        app.MapGet("/api/fixed-cves", async (Engine engine, string? branch) =>
            Ok(await engine.RunJsonAsync("fixed-cves", string.IsNullOrEmpty(branch) ? "3.0" : branch)));

        // ---- VulnerabilityData feed (read by the Python engine) ----
        async Task<object?> Feed(Engine engine, params string[] args)
        {
            try { return await engine.RunJsonAsync(args); }
            catch (FeedException ex) { throw new HttpError(502, ex.Message); }
        }

        app.MapGet("/api/vulnerability-data", async (Engine engine, bool refresh = false) =>
            Ok(await Feed(engine, refresh ? new[] { "vuln-summary", "--refresh" } : new[] { "vuln-summary" })));

        app.MapGet("/api/vulnerability-data/packages", async (Engine engine, string? search, int page = 1, int limit = 50, bool refresh = false) =>
        {
            CheckLimit(limit, 500);
            var raw = await Feed(engine, refresh ? new[] { "vuln-packages", "--refresh" } : new[] { "vuln-packages" });
            var packages = (raw as List<object?> ?? new List<object?>()).OfType<Row>().ToList();
            if (!string.IsNullOrEmpty(search))
            {
                var needle = search.ToLowerInvariant();
                packages = packages.Where(p => p.Str("name").ToLowerInvariant().Contains(needle)).ToList();
            }
            var start = (Math.Max(page, 1) - 1) * limit;
            return Ok(new Row { ["items"] = packages.Skip(start).Take(limit).ToList(), ["total"] = packages.Count, ["page"] = page, ["limit"] = limit });
        });

        app.MapGet("/api/vulnerability-data/packages/{name}", async (Engine engine, string name, bool refresh = false) =>
        {
            var args = refresh ? new[] { "vuln-package", name, "--refresh" } : new[] { "vuln-package", name };
            var pkg = await Feed(engine, args);
            if (pkg is null) throw new HttpError(404, "Package not found in the VulnerabilityData feed");
            return Ok(pkg);
        });

        // ---- triage ----
        app.MapGet("/api/triage", (IDbFactory db, string? status, string? search, int page = 1, int limit = 50) =>
        {
            CheckLimit(limit, 200);
            using var conn = db.Open();
            var (rows, total) = Repo.ListTriage(conn, Cfg.OpenStatus, search ?? "", limit, (Math.Max(page, 1) - 1) * limit);
            foreach (var row in rows) Triage.DecorateFinding(row, null);
            return Ok(new Row { ["items"] = rows, ["total"] = total, ["page"] = page, ["limit"] = limit });
        });

        app.MapGet("/api/triage/comments", (IDbFactory db, string? cve_id, string? branch, string? spec_path) =>
        {
            if (cve_id is null || cve_id.Length < 4 || cve_id.Length > 32)
                throw new HttpError(422, "cve_id must be 4 to 32 characters.");
            using var conn = db.Open();
            var comments = Repo.FindingComments(conn, cve_id.ToUpperInvariant(), branch, spec_path);
            return Ok(new Row { ["items"] = comments, ["total"] = comments.Count });
        });

        app.MapPost("/api/triage/comment", async (HttpRequest req, IDbFactory db, AuthService auth) =>
        {
            var role = auth.RequireCapability(req, "comment", "comment on a finding");
            var payload = await Body<CommentRequest>(req);
            var body = Trimmed(payload.Body);
            if (body.Length == 0) throw new HttpError(400, "Comment body is required");
            if (string.IsNullOrEmpty(payload.CveId)) throw new HttpError(400, "cve_id is required");
            var author = auth.ActorIdentity(req, role);
            using var conn = db.Open();
            var comment = Repo.AddFindingComment(conn, payload.CveId.ToUpperInvariant(), payload.Branch, payload.SpecPath, body, author);
            return Ok(new Row { ["comment"] = comment, ["role"] = role });
        });

        app.MapPost("/api/triage/dispute", async (HttpRequest req, IDbFactory db, AuthService auth) =>
        {
            var role = auth.RequireCapability(req, "dispute", "raise a dispute");
            var payload = await Body<DisputeRequest>(req);
            var reason = Trimmed(payload.Reason);
            if (reason.Length == 0) throw new HttpError(400, "A dispute needs a reason");
            if (string.IsNullOrEmpty(payload.CveId)) throw new HttpError(400, "cve_id is required");
            var version = Trimmed(payload.FirstUnaffectedVersion);
            if (payload.NeverApplicable) reason += "\nApplicability: Never Applicable";
            else if (version.Length > 0)
            {
                if (!Regex.IsMatch(version, @"^[A-Za-z0-9._+~^-]+$"))
                    throw new HttpError(400, "First unaffected version contains unsupported characters");
                reason += $"\nFirst unaffected version: {version}";
            }
            var cveId = payload.CveId.ToUpperInvariant();
            var requester = auth.ActorIdentity(req, role);
            using var conn = db.Open();
            var finding = Repo.GetFindingAt(conn, cveId, payload.Branch, payload.SpecPath);
            if (finding is null) throw new HttpError(404, "Finding not found");
            if (Repo.PendingDispute(conn, cveId, payload.Branch, payload.SpecPath) is not null)
                throw new HttpError(409, "A dispute for this package is already waiting for approval.");
            var auto = Roles.Has(role, "approve_dispute");
            var dispute = Repo.CreateDispute(conn, finding, reason, requester, payload.NeverApplicable ? "" : version,
                payload.NeverApplicable, auto ? "approved" : "pending");
            var applied = auto ? ApplyApprovedDispute(conn, dispute) : new Row();
            return Ok(Merge(new Row { ["dispute"] = dispute, ["approved"] = auto }, applied));
        });

        app.MapGet("/api/disputes", (IDbFactory db, string? status, string? search, int page = 1, int limit = 50) =>
        {
            CheckLimit(limit, 200);
            status ??= "";
            if (status.Length > 0 && !Repo.DisputeStatuses.Contains(status))
                throw new HttpError(400, "status must be pending, approved or rejected");
            using var conn = db.Open();
            var (rows, total) = Repo.ListDisputes(conn, status, Trimmed(search), limit, (Math.Max(page, 1) - 1) * limit);
            var counts = Repo.DisputeCounts(conn);
            return Ok(new Row { ["items"] = rows, ["total"] = total, ["page"] = page, ["limit"] = limit, ["counts"] = counts });
        });

        async Task<IResult> Decide(HttpRequest req, IDbFactory db, AuthService auth, long dispute_id, string status)
        {
            var role = auth.RequireCapability(req, "approve_dispute", "approve or reject disputes");
            var payload = await OptionalBody<DisputeDecision>(req) ?? new DisputeDecision();
            var decider = auth.ActorIdentity(req, role);
            using var conn = db.Open();
            if (Repo.GetDispute(conn, dispute_id) is null) throw new HttpError(404, "Dispute not found");
            var dispute = Repo.DecideDispute(conn, dispute_id, status, decider, Trimmed(payload.Note));
            if (dispute is null) throw new HttpError(409, "This dispute has already been decided.");
            var applied = status == "approved" ? ApplyApprovedDispute(conn, dispute) : new Row();
            return Ok(Merge(new Row { ["dispute"] = dispute }, applied));
        }

        app.MapPost("/api/disputes/{dispute_id:long}/approve", (HttpRequest req, IDbFactory db, AuthService auth, long dispute_id) =>
            Decide(req, db, auth, dispute_id, "approved"));
        app.MapPost("/api/disputes/{dispute_id:long}/reject", (HttpRequest req, IDbFactory db, AuthService auth, long dispute_id) =>
            Decide(req, db, auth, dispute_id, "rejected"));

        async Task<IResult> SetGithubPr(HttpRequest req, IDbFactory db, AuthService auth)
        {
            var role = auth.RequirePrSetter(req);
            var payload = await Body<GithubPrRequest>(req);
            var number = Trimmed(payload.Number).TrimStart('#');
            if (!IsDigits(number)) throw new HttpError(400, "PR number must contain digits only");
            var cveId = payload.CveId.ToUpperInvariant();
            var url = Trimmed(payload.Url);
            if (url.Length == 0) url = $"https://github.com/{Cfg.PatchTargetRepo}/pull/{number}";
            // A URL is only an association, not proof of a fix: a canonical GitHub pull-request
            // URL whose number matches the PR number.
            if (!Regex.IsMatch(url, @"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/" + Regex.Escape(number) + "/?$"))
                throw new HttpError(400, "Use a GitHub pull request URL whose number matches the PR number field");
            var identity = auth.ActorIdentity(req, role);
            var owner = role == Cfg.RoleDeveloper ? identity : (Cfg.AdminEmail.Length > 0 ? Cfg.AdminEmail : Cfg.AdminIdentity);
            using var conn = db.Open();
            var record = Repo.UpsertTriage(conn, cveId, payload.Branch, payload.SpecPath, new Dictionary<string, object?>
            {
                ["github_pr_number"] = number, ["github_pr_url"] = url, ["github_pr_set_by"] = identity,
                ["github_pr_set_at"] = Sql.UtcNow(), ["resolution_status"] = "in_progress", ["owner"] = owner,
            });
            if (req.Path.Value?.EndsWith("/google-pr") == true)
            {
                // Backward-compatible response names for the original automation client.
                record = Merge(record, new Row
                {
                    ["google_pr_number"] = record.Str("github_pr_number"), ["google_pr_url"] = record.Str("github_pr_url"),
                    ["google_pr_set_by"] = record.Str("github_pr_set_by"), ["google_pr_set_at"] = record.Str("github_pr_set_at"),
                });
            }
            return Ok(new Row { ["triage"] = record, ["role"] = role, ["identity"] = identity });
        }
        app.MapPost("/api/triage/google-pr", SetGithubPr);
        app.MapPost("/api/triage/github-pr", SetGithubPr);

        app.MapPost("/api/triage/patch", async (HttpRequest req, IDbFactory db, AuthService auth) =>
        {
            auth.RequireAdmin(req);
            var payload = await Body<PatchVerdictRequest>(req);
            using var conn = db.Open();
            var record = Repo.UpsertTriage(conn, payload.CveId.ToUpperInvariant(), payload.Branch, payload.SpecPath,
                new Dictionary<string, object?>
                {
                    ["final_verdict"] = Trimmed(payload.FinalVerdict), ["patch_link"] = Trimmed(payload.PatchLink),
                    ["available_since"] = Trimmed(payload.AvailableSince),
                });
            return Ok(new Row { ["triage"] = record });
        });

        app.MapPost("/api/triage/claim", async (HttpRequest req, IDbFactory db, AuthService auth) =>
        {
            var (role, me) = auth.RequireClaimer(req);
            var payload = await Body<FindingRef>(req);
            var cveId = payload.CveId.ToUpperInvariant();
            using var conn = db.Open();
            var current = Trimmed(Repo.GetTriage(conn, cveId, payload.Branch, payload.SpecPath)?.Str("owner"));
            if (current.Length > 0 && current.ToLowerInvariant() != me && role != Cfg.RoleAdmin)
                throw new HttpError(409, $"Already claimed by {current}.");
            var record = Repo.UpsertTriage(conn, cveId, payload.Branch, payload.SpecPath, new Dictionary<string, object?> { ["owner"] = me });
            return Ok(new Row { ["triage"] = record });
        });

        app.MapPost("/api/triage/release", async (HttpRequest req, IDbFactory db, AuthService auth) =>
        {
            var (role, me) = auth.RequireClaimer(req);
            var payload = await Body<FindingRef>(req);
            var cveId = payload.CveId.ToUpperInvariant();
            using var conn = db.Open();
            var current = Trimmed(Repo.GetTriage(conn, cveId, payload.Branch, payload.SpecPath)?.Str("owner"));
            if (current.Length > 0 && current.ToLowerInvariant() != me && role != Cfg.RoleAdmin)
                throw new HttpError(409, $"Claimed by {current}; only they or the administrator can release it.");
            var record = Repo.UpsertTriage(conn, cveId, payload.Branch, payload.SpecPath, new Dictionary<string, object?> { ["owner"] = "" });
            return Ok(new Row { ["triage"] = record });
        });

        app.MapGet("/api/workflows", (HttpRequest req, IDbFactory db, AuthService auth) =>
        {
            var (_, me) = auth.RequireClaimer(req);
            List<Row> rows;
            using (var conn = db.Open())
            {
                (rows, _) = Repo.ListFindings(conn, new Repo.FindingFilter(), 1_000_000, 0);
                DecorateFindings(conn, rows, slim: true);
            }
            var groups = new Dictionary<string, List<Row>> { [me] = new() };
            foreach (var row in rows)
            {
                var assigned = (row.Sub("assignment")?.Str("assignee_email") ?? "").Trim().ToLowerInvariant();
                var claimed = (row.Sub("triage")?.Str("owner") ?? "").Trim().ToLowerInvariant();
                var owner = assigned.Length > 0 ? assigned : claimed;
                if (owner.Length == 0) continue;
                row["held_via"] = assigned.Length > 0 ? "assigned" : "claimed";
                if (!groups.TryGetValue(owner, out var list)) groups[owner] = list = new List<Row>();
                list.Add(row);
            }
            var ordered = new List<string> { me };
            ordered.AddRange(groups.Keys.Where(e => e != me).OrderBy(e => e, StringComparer.Ordinal));
            return Ok(new Row
            {
                ["me"] = me, ["owner"] = me, ["total"] = groups.Values.Sum(l => l.Count),
                ["groups"] = ordered.Select(e => new Row { ["owner"] = e, ["total"] = groups[e].Count, ["items"] = groups[e] }).ToList(),
            });
        });

        // ---- automation ----
        app.MapGet("/api/automation", (HttpRequest req, IDbFactory db, AuthService auth) =>
        {
            auth.RequireClaimer(req);
            using var conn = db.Open();
            var packages = AutomationPackages(conn);
            return Ok(new Row
            {
                ["owner"] = Cfg.AutomationEmail.Trim().ToLowerInvariant(),
                ["total"] = packages.Sum(g => ((List<Row>)g["items"]!).Count),
                ["packages"] = packages,
            });
        });

        app.MapPost("/api/automation/requests", async (HttpRequest req, IDbFactory db, AuthService auth, ResponseCache cache, HttpClient http) =>
        {
            var (_, me) = auth.RequireClaimer(req);
            var payload = await Body<AutomationRequest>(req);
            var mode = Trimmed(payload.Mode);
            if (mode is not ("new_pr" or "existing_pr"))
                throw new HttpError(400, "Choose either a new PR or an existing PR");
            var number = "";
            if (mode == "existing_pr")
            {
                number = Trimmed(payload.PrNumber).TrimStart('#');
                if (!IsDigits(number)) throw new HttpError(400, "Enter the PR number (digits only)");
            }
            var wanted = payload.CveIds.Select(c => c.Trim().ToUpperInvariant()).Where(c => c.Length > 0).Distinct()
                .OrderBy(c => c, StringComparer.Ordinal).ToList();
            if (wanted.Count == 0) throw new HttpError(400, "Tick at least one CVE");
            var key = (payload.PackageName, payload.Branch ?? "", payload.SpecPath ?? "");
            Row record;
            using (var conn = db.Open())
            {
                var group = AutomationPackages(conn).FirstOrDefault(g => (g.Str("package_name"), g.Str("branch"), g.Str("spec_path")) == key);
                if (group is not null && group.Get("busy") is true)
                    throw new HttpError(409, "A request for this package is already queued or running.");
                var allowed = group is null ? new HashSet<string>() : ((List<Row>)group["items"]!).Select(i => i.Str("cve_id")).ToHashSet();
                if (group is null || !wanted.All(allowed.Contains))
                    throw new HttpError(400, "Those CVEs are not ready for automation on this package");
                record = Repo.CreateAutomationRequest(conn, key.Item1, key.Item2, key.Item3, wanted, mode, number, me);
            }
            cache.Clear();
            await DispatchRunnerAsync(http);
            return Ok(new Row { ["request"] = record });
        });

        app.MapPost("/api/automation/jobs/next", (HttpRequest req, IDbFactory db, AuthService auth) =>
        {
            auth.RequireAutomation(req);
            using var conn = db.Open();
            var claimed = Repo.ClaimAutomationRequest(conn);
            if (claimed is null) return Ok(new Row { ["job"] = null });
            var key = (claimed.Str("package_name"), claimed.Str("branch"), claimed.Str("spec_path"));
            var group = AutomationPackages(conn).FirstOrDefault(g => (g.Str("package_name"), g.Str("branch"), g.Str("spec_path")) == key);
            var wanted = ((List<object?>)claimed["cve_ids"]!).Select(x => Convert.ToString(x) ?? "").ToHashSet();
            var items = group is null ? new List<Row>() : ((List<Row>)group["items"]!).Where(i => wanted.Contains(i.Str("cve_id"))).ToList();
            if (items.Count == 0)
            {
                Repo.FinishAutomationRequest(conn, claimed.Long("id"), "failed", "None of the CVEs are ready any more.", "", "", "");
                return Ok(new Row { ["job"] = null });
            }
            return Ok(new Row
            {
                ["job"] = new Row
                {
                    ["id"] = claimed.Get("id"), ["package_name"] = claimed.Get("package_name"), ["spec_path"] = claimed.Get("spec_path"),
                    ["mode"] = claimed.Get("mode"), ["pr_number"] = claimed.Get("pr_number"),
                    ["cves"] = items.Select(i => new Row
                    {
                        ["cve_id"] = i.Get("cve_id"), ["severity"] = i.Str("severity"), ["description"] = i.Str("description"),
                        ["patch_link"] = i.Sub("patch_availability")?.Str("patch_link") ?? "",
                        ["branch"] = i.Str("branch"), ["spec_path"] = i.Str("spec_path"),
                    }).ToList(),
                },
            });
        });

        app.MapPost("/api/automation/jobs/{job_id:long}/result", async (HttpRequest req, IDbFactory db, AuthService auth, ResponseCache cache, long job_id) =>
        {
            auth.RequireAutomation(req);
            var payload = await Body<JobResult>(req);
            if (payload.Status is not ("done" or "partial" or "failed"))
                throw new HttpError(400, "status must be done, partial or failed");
            Row? record;
            using (var conn = db.Open())
            {
                var message = payload.Message.Length > 2000 ? payload.Message[..2000] : payload.Message;
                record = Repo.FinishAutomationRequest(conn, job_id, payload.Status, message, payload.PrUrl,
                    payload.PrNumber.TrimStart('#'), payload.BranchName);
            }
            if (record is null) throw new HttpError(404, "No such request");
            cache.Clear();
            return Ok(new Row { ["request"] = record });
        });

        // ---- rescore ----
        app.MapPost("/api/cves/{cve_id}/rescore", async (HttpRequest req, IDbFactory db, AuthService auth, string cve_id) =>
        {
            var role = auth.RequireAdmin(req);
            var payload = await Body<RescoreRequest>(req);
            var cveId = cve_id.ToUpperInvariant();
            var severity = Trimmed(payload.Severity).ToLowerInvariant();
            if (severity is not ("critical" or "high" or "medium" or "low" or "none"))
                throw new HttpError(400, "Severity must be critical, high, medium, low or none");
            if (payload.CvssScore is { } s && (s < 0 || s > 10))
                throw new HttpError(400, "CVSS score must be between 0 and 10");
            var reason = Trimmed(payload.Reason);
            if (reason.Length == 0) throw new HttpError(400, "A rescore needs a reason");
            using var conn = db.Open();
            if (Repo.FindingsForCve(conn, cveId).Count == 0) throw new HttpError(404, "CVE not found in the current scan");
            var record = Repo.SetRescore(conn, cveId, severity, payload.CvssScore, reason, auth.ActorIdentity(req, role));
            return Ok(new Row { ["rescore"] = record });
        });

        // ---- assignment queue ----
        app.MapGet("/api/assignments", (IDbFactory db) =>
        {
            using var conn = db.Open();
            return Ok(new Row { ["items"] = Repo.ListAssignments(conn) });
        });

        app.MapPost("/api/assignments", async (HttpRequest req, IDbFactory db, AuthService auth) =>
        {
            auth.RequireAdmin(req);
            var payload = await Body<AssignmentRequest>(req);
            var target = string.IsNullOrEmpty(payload.TargetRepo) ? Cfg.PatchTargetRepo : payload.TargetRepo;
            var assignee = Trimmed(payload.AssigneeEmail).ToLowerInvariant();
            if (assignee.Length > 0 && !Roles.AssignableEmails.Contains(assignee))
                throw new HttpError(400, "Choose an assignee from the configured demo assignment list.");
            using var conn = db.Open();
            var finding = Repo.GetFinding(conn, payload.CveId.ToUpperInvariant(), payload.PackageName, payload.SpecPath);
            if (finding is null) throw new HttpError(404, "Finding not found");
            var record = Repo.CreateAssignment(conn, payload.CveId.ToUpperInvariant(), payload.PackageName, target, payload.Notes, assignee);
            return Ok(new Row
            {
                ["assignment"] = record,
                ["workflow"] = "VULNEX -> Patch Automation queue -> AI Patch/Backport Agent -> Security Review Agent -> PR Agent -> GitHub Pull Request",
                ["target_repo"] = target,
            });
        });

        app.MapMethods("/api/assignments/{assignment_id:long}", new[] { "PATCH" }, (HttpRequest req, IDbFactory db, AuthService auth, long assignment_id, string? status) =>
        {
            auth.RequireAdmin(req);
            if (status is null) throw new HttpError(422, "status is required.");
            using var conn = db.Open();
            var record = Repo.UpdateAssignment(conn, assignment_id, status);
            if (record is null) throw new HttpError(404, "Assignment not found");
            return Ok(new Row { ["assignment"] = record });
        });

        app.MapPost("/api/assignments/{assignment_id:long}/comments", async (HttpRequest req, IDbFactory db, AuthService auth, long assignment_id) =>
        {
            auth.RequireAdmin(req);
            var payload = await Body<CommentRequest>(req);
            var body = Trimmed(payload.Body);
            if (body.Length == 0) throw new HttpError(400, "Comment body is required");
            using var conn = db.Open();
            if (Repo.GetAssignment(conn, assignment_id) is null) throw new HttpError(404, "Assignment not found");
            var author = Trimmed(string.IsNullOrEmpty(payload.Author) ? Cfg.AdminIdentity : payload.Author);
            return Ok(new Row { ["comment"] = Repo.AddComment(conn, assignment_id, body, author) });
        });

        // ---- scan control ----
        app.MapPost("/api/scan", async (HttpRequest req, AuthService auth, ScanManager scans) =>
        {
            auth.RequireAdmin(req);
            var payload = await OptionalBody<ScanRequest>(req) ?? new ScanRequest();
            var requested = payload.Branches is { Count: > 0 } ? payload.Branches : new List<string> { "3.0", "4.0" };
            var invalid = requested.Distinct().Where(b => b is not ("3.0" or "4.0")).OrderBy(b => b, StringComparer.Ordinal).ToList();
            if (invalid.Count > 0)
                throw new HttpError(400, $"Unsupported branch(es): {string.Join(", ", invalid)}. Choose a branch from azurelinux-test.");
            var ecosystem = requested.All(b => b == "4.0") ? "Azure Linux:4"
                : requested.All(b => b == "3.0") ? "Azure Linux:3"
                : "Azure Linux:3+Azure Linux:4";
            var started = scans.Start(new Row
            {
                ["branches"] = requested,
                ["ecosystem"] = ecosystem,
                ["packages"] = payload.Packages is { Count: > 0 } ? payload.Packages : null,
                ["limit"] = payload.Limit,
                ["verify_blobs"] = payload.VerifyBlobs,
                ["enrich"] = payload.Enrich,
            });
            return started ? Status(202, new Row { ["status"] = "started" }) : Status(409, new Row { ["detail"] = "A scan is already running" });
        });

        app.MapGet("/api/scan/status", (IDbFactory db, ScanManager scans) =>
        {
            using var conn = db.Open();
            return Ok(new Row { ["manager"] = scans.Status(), ["latest_scan"] = Repo.LatestScan(conn) });
        });

        app.MapGet("/api/scans", (IDbFactory db) =>
        {
            using var conn = db.Open();
            return Ok(new Row { ["items"] = Repo.ScanHistory(conn) });
        });
    }
}
