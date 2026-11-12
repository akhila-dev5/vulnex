using System.Text.Json;

namespace Vulnex.Api;

/// <summary>Finding identity: (cve_id, branch, spec_path).</summary>
public readonly record struct FindingKey(string CveId, string Branch, string SpecPath)
{
    public static FindingKey Of(Row r) => new(r.Str("cve_id"), r.Str("branch"), r.Str("spec_path"));
}

/// <summary>
/// Queries against the existing PostgreSQL schema (owned by Alembic). A line-for-line
/// port of the read/write functions in the Python <c>db.py</c>, so every endpoint
/// returns the same rows in the same shape.
/// </summary>
public static class Repo
{
    const string StatusRankTemplate =
        "CASE {p}status WHEN 'affected' THEN 0 WHEN 'unconfirmed' THEN 1 " +
        "WHEN 'patched' THEN 2 WHEN 'false_positive' THEN 3 ELSE 4 END";

    static string StatusRank(string prefix) => StatusRankTemplate.Replace("{p}", prefix);

    static readonly string EffectiveSeverity =
        "COALESCE((SELECT r.severity FROM cve_rescores r WHERE r.cve_id = findings.cve_id), severity)";

    public static readonly string[] DisputeStatuses = { "pending", "approved", "rejected" };

    static readonly string[] TriageFields =
    {
        "package_name", "triage_status", "resolution_status", "final_verdict", "patch_link",
        "available_since", "github_pr_number", "github_pr_url", "github_pr_set_by",
        "github_pr_set_at", "owner", "vuln_id", "qualys_ids",
    };

    // -- helpers ------------------------------------------------------------
    static List<object?> EmptyList() => new();

    static Row HydrateFinding(Row f)
    {
        var refs = f.Get("refs");
        f.Remove("refs");
        f["references"] = Sql.Loads(refs, EmptyList);
        f["affected_files"] = Sql.Loads(f.Get("affected_files"), EmptyList);
        f["corroborating_sources"] = Sql.Loads(f.Get("corroborating_sources"), EmptyList);
        f["evidence"] = Sql.Loads(f.Get("evidence"), EmptyList);
        f["raw_sources"] = Sql.Loads(f.Get("raw_sources"), EmptyList);
        return f;
    }

    static Row ApplyRescore(Row f, Row rescore)
    {
        f["scanned_severity"] = f.Get("severity");
        f["scanned_cvss_score"] = f.Get("cvss_score");
        f["severity"] = rescore.Get("severity");
        f["cvss_score"] = rescore.Get("cvss_score");
        f["rescore"] = new Row
        {
            ["severity"] = rescore.Get("severity"),
            ["cvss_score"] = rescore.Get("cvss_score"),
            ["reason"] = rescore.Str("reason"),
            ["rescored_by"] = rescore.Str("rescored_by"),
            ["rescored_at"] = rescore.Str("rescored_at"),
        };
        return f;
    }

    // -- scans ----------------------------------------------------------------
    public static Row? LatestScan(DbConnection c) =>
        Sql.One(c, "SELECT * FROM scans ORDER BY id DESC LIMIT 1");

    public static List<Row> ScanHistory(DbConnection c, int limit = 20) =>
        Sql.Query(c, "SELECT * FROM scans ORDER BY id DESC LIMIT @n", ("n", limit));

    public static Row Stats(DbConnection c, string? branch)
    {
        if (!string.IsNullOrEmpty(branch) && branch is not ("3.0" or "4.0"))
            throw new ArgumentException("Stats can only be scoped to stable branch 3.0 or 4.0");
        var hasBranch = !string.IsNullOrEmpty(branch);
        (string, object?)[] bp = hasBranch ? new (string, object?)[] { ("branch", branch) } : Array.Empty<(string, object?)>();
        var branchWhere = hasBranch ? " WHERE branch = @branch" : "";

        var packages = Sql.Count(c, "SELECT COUNT(*) FROM packages" + branchWhere, bp);
        var total = Sql.Count(c, "SELECT COUNT(*) FROM findings" + branchWhere, bp);

        long Count(string table, params string[] where)
        {
            var clauses = where.ToList();
            if (hasBranch) clauses.Add("branch = @branch");
            var sql = $"SELECT COUNT(*) FROM {table}";
            if (clauses.Count > 0) sql += " WHERE " + string.Join(" AND ", clauses);
            return Sql.Count(c, sql, bp);
        }

        var openWhere = $"status = '{Cfg.OpenStatus}'";
        var openTotal = Count("findings", openWhere);
        var severity = new Row();
        foreach (var s in new[] { "critical", "high", "medium", "low", "none", "unknown" })
            severity[s] = Count("findings", $"{openWhere} AND {EffectiveSeverity} = '{s}'");

        Row? scan;
        if (hasBranch)
        {
            scan = ScanHistory(c, 100).FirstOrDefault(item =>
                item.Str("branches").Split(',').Contains(branch) && item.Str("status") == "success");
        }
        else
        {
            scan = LatestScan(c);
        }

        var distinctWhere = openWhere + (hasBranch ? " AND branch = @branch" : "");
        return new Row
        {
            ["total_packages"] = packages,
            ["total_findings"] = openTotal,
            ["affected"] = openTotal,
            ["severity"] = severity,
            ["distinct_cves"] = Sql.Count(c, $"SELECT COUNT(DISTINCT cve_id) FROM findings WHERE {distinctWhere}", bp),
            ["patched"] = Count("findings", "status = 'patched'"),
            ["false_positive"] = Count("findings", "status = 'false_positive'"),
            ["unconfirmed"] = Count("findings", "status = 'unconfirmed'"),
            ["excluded_findings"] = total - openTotal,
            ["total_patches"] = Count("patches"),
            ["nopatch_markers"] = Count("patches", "is_nopatch = 1"),
            ["last_scan"] = scan ?? new Row(),
            ["assignments"] = Sql.Count(c, "SELECT COUNT(*) FROM assignments"),
        };
    }

    // -- packages -------------------------------------------------------------
    public static (List<Row> Rows, long Total) ListPackages(DbConnection c, string search, string branch,
        int limit, int offset, List<string>? branches)
    {
        var clauses = new List<string>();
        var ps = new List<(string, object?)>();
        if (search.Length > 0) { clauses.Add("name ILIKE @search"); ps.Add(("search", $"%{search}%")); }
        if (branches is { Count: > 0 })
            clauses.Add($"branch IN ({Sql.InList("b", branches, ps)})");
        else if (branch.Length > 0) { clauses.Add("branch = @branch"); ps.Add(("branch", branch)); }
        var where = clauses.Count > 0 ? " WHERE " + string.Join(" AND ", clauses) : "";
        var total = Sql.Count(c, $"SELECT COUNT(*) FROM packages{where}", ps.ToArray());
        var pageParams = new List<(string, object?)>(ps) { ("lim", limit), ("off", offset) };
        var rows = Sql.Query(c, $"SELECT * FROM packages{where} ORDER BY name, version LIMIT @lim OFFSET @off", pageParams.ToArray());

        var counts = new Dictionary<(string, string), Row>();
        var specPaths = rows.Select(r => r.Str("spec_path")).Where(s => s.Length > 0).Distinct().OrderBy(s => s, StringComparer.Ordinal).ToList();
        if (specPaths.Count > 0)
        {
            var gp = new List<(string, object?)>();
            var marks = Sql.InList("s", specPaths, gp);
            gp.Add(("open", Cfg.OpenStatus));
            var grouped = Sql.Query(c,
                $"SELECT branch, spec_path, status, COUNT(*) AS c FROM findings WHERE spec_path IN ({marks}) AND status = @open GROUP BY branch, spec_path, status",
                gp.ToArray());
            foreach (var g in grouped)
            {
                var key = (g.Str("branch"), g.Str("spec_path"));
                if (!counts.TryGetValue(key, out var bucket)) counts[key] = bucket = new Row();
                bucket[g.Str("status")] = g.Get("c");
            }
        }
        foreach (var row in rows)
        {
            row["source_urls"] = Sql.Loads(row.Get("source_urls"), EmptyList);
            row["finding_counts"] = counts.TryGetValue((row.Str("branch"), row.Str("spec_path")), out var b) ? b : new Row();
        }
        return (rows, total);
    }

    public static Row? GetPackage(DbConnection c, string name, string? branch, string? specPath)
    {
        Row? row;
        if (!string.IsNullOrEmpty(specPath) && !string.IsNullOrEmpty(branch))
            row = Sql.One(c, "SELECT * FROM packages WHERE spec_path = @s AND branch = @b", ("s", specPath), ("b", branch));
        else if (!string.IsNullOrEmpty(specPath))
            row = Sql.One(c, "SELECT * FROM packages WHERE spec_path = @s ORDER BY is_primary DESC, id LIMIT 1", ("s", specPath));
        else if (!string.IsNullOrEmpty(branch))
            row = Sql.One(c, "SELECT * FROM packages WHERE name = @n AND branch = @b ORDER BY is_primary DESC, id LIMIT 1", ("n", name), ("b", branch));
        else
            row = Sql.One(c, "SELECT * FROM packages WHERE name = @n ORDER BY is_primary DESC, branch, id LIMIT 1", ("n", name));
        if (row is null) return null;

        row["source_urls"] = Sql.Loads(row.Get("source_urls"), EmptyList);
        var pb = ("b", (object?)row.Get("branch"));
        var ps = ("s", (object?)row.Get("spec_path"));
        var patches = Sql.Query(c, "SELECT * FROM patches WHERE branch = @b AND spec_path = @s ORDER BY id", pb, ps);
        foreach (var p in patches) p["cve_ids"] = Sql.Loads(p.Get("cve_ids"), EmptyList);
        row["patches"] = patches;
        var findings = Sql.Query(c, "SELECT * FROM findings WHERE branch = @b AND spec_path = @s ORDER BY severity, cve_id", pb, ps);
        foreach (var f in findings) HydrateFinding(f);
        row["findings"] = findings;
        row["variants"] = Sql.Query(c,
            "SELECT branch, spec_path, version, release, evr, is_primary FROM packages WHERE name = @n ORDER BY is_primary DESC, branch, version",
            ("n", row.Get("name")));
        return row;
    }

    // -- findings -------------------------------------------------------------
    public sealed record FindingFilter
    {
        public string Status { get; init; } = "";
        public string Severity { get; init; } = "";
        public string Search { get; init; } = "";
        public string Package { get; init; } = "";
        public string Branch { get; init; } = "";
        public List<string>? Branches { get; init; }
        public string TriageStatus { get; init; } = "";
        public string ResolutionStatus { get; init; } = "";
        public string Owner { get; init; } = "";
        public string FixedVersion { get; init; } = "";
    }

    public static (List<Row> Rows, long Total) ListFindings(DbConnection c, FindingFilter f, int limit, int offset)
    {
        var clauses = new List<string>();
        var ps = new List<(string, object?)>();
        if (f.Status.Length > 0) { clauses.Add("f.status = @status"); ps.Add(("status", f.Status)); }
        if (f.Severity.Length > 0) { clauses.Add("COALESCE(rs.severity, f.severity) = @severity"); ps.Add(("severity", f.Severity)); }
        if (f.Package.Length > 0) { clauses.Add("f.package_name = @package"); ps.Add(("package", f.Package)); }
        if (f.Branches is { Count: > 0 })
            clauses.Add($"f.branch IN ({Sql.InList("br", f.Branches, ps)})");
        else if (f.Branch.Length > 0) { clauses.Add("f.branch = @branch"); ps.Add(("branch", f.Branch)); }
        if (f.Search.Length > 0)
        {
            clauses.Add("(f.cve_id ILIKE @like OR f.package_name ILIKE @like OR f.description ILIKE @like OR f.advisory_id ILIKE @like)");
            ps.Add(("like", $"%{f.Search}%"));
        }

        var join = " LEFT JOIN cve_rescores rs ON rs.cve_id = f.cve_id";
        if (f.TriageStatus.Length > 0 || f.ResolutionStatus.Length > 0 || f.Owner.Length > 0)
            join += " LEFT JOIN finding_triage t ON t.cve_id = f.cve_id" +
                    " AND t.branch = COALESCE(f.branch, '') AND t.spec_path = COALESCE(f.spec_path, '')";
        if (f.TriageStatus.Length > 0)
        {
            clauses.Add("LOWER(COALESCE(NULLIF(t.triage_status, ''), 'open')) = @ts");
            ps.Add(("ts", f.TriageStatus.ToLowerInvariant()));
        }
        if (f.ResolutionStatus.Length > 0)
        {
            clauses.Add("LOWER(COALESCE(NULLIF(t.resolution_status, ''), f.status, '')) = @rs");
            ps.Add(("rs", f.ResolutionStatus.ToLowerInvariant()));
        }
        if (f.Owner.Length > 0)
        {
            clauses.Add("LOWER(COALESCE(t.owner, '')) LIKE @owner");
            ps.Add(("owner", $"%{f.Owner.ToLowerInvariant()}%"));
        }
        if (f.FixedVersion.Length > 0)
        {
            clauses.Add("f.status = 'patched' AND LOWER(COALESCE(f.fixed_in, '')) LIKE @fv");
            ps.Add(("fv", $"%{f.FixedVersion.ToLowerInvariant()}%"));
        }

        var where = clauses.Count > 0 ? " WHERE " + string.Join(" AND ", clauses) : "";
        var total = Sql.Count(c, $"SELECT COUNT(*) FROM findings f{join}{where}", ps.ToArray());
        var rank = StatusRank("f.");
        var sev = "CASE COALESCE(rs.severity, f.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 " +
                  "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'none' THEN 4 ELSE 5 END";
        var order = $"cve_rank, cve_new DESC, cve_sev, f.cve_id, {rank}, " +
                    "COALESCE(f.first_seen, '') DESC, f.confidence DESC, f.package_name";
        var page = new List<(string, object?)>(ps) { ("lim", limit), ("off", offset) };
        var rows = Sql.Query(c,
            "SELECT f.*, rs.severity AS rs_severity, rs.cvss_score AS rs_score, rs.reason AS rs_reason, " +
            "rs.rescored_by AS rs_by, rs.rescored_at AS rs_at, " +
            $"MIN({rank}) OVER (PARTITION BY f.cve_id) AS cve_rank, " +
            $"MIN({sev}) OVER (PARTITION BY f.cve_id) AS cve_sev, " +
            $"MAX(CASE WHEN {rank} = 0 THEN COALESCE(f.first_seen, '') ELSE '' END) OVER (PARTITION BY f.cve_id) AS cve_new " +
            $"FROM findings f{join}{where} ORDER BY {order} LIMIT @lim OFFSET @off",
            page.ToArray());
        foreach (var r in rows)
        {
            r.Remove("cve_rank"); r.Remove("cve_sev"); r.Remove("cve_new");
            HydrateFinding(r);
            var sevO = r.Get("rs_severity");
            var scoreO = r.Get("rs_score");
            var reason = r.Get("rs_reason");
            var by = r.Get("rs_by");
            var at = r.Get("rs_at");
            foreach (var k in new[] { "rs_severity", "rs_score", "rs_reason", "rs_by", "rs_at" }) r.Remove(k);
            if (sevO is string { Length: > 0 })
                ApplyRescore(r, new Row { ["severity"] = sevO, ["cvss_score"] = scoreO, ["reason"] = reason, ["rescored_by"] = by, ["rescored_at"] = at });
        }
        return (rows, total);
    }

    public static Row? GetRescore(DbConnection c, string cveId) =>
        Sql.One(c, "SELECT * FROM cve_rescores WHERE cve_id = @c", ("c", cveId));

    public static Row SetRescore(DbConnection c, string cveId, string severity, double? cvssScore, string reason, string rescoredBy)
    {
        var previous = GetRescore(c, cveId);
        object? origSeverity, origScore;
        if (previous is not null)
        {
            origSeverity = previous.Get("original_severity");
            origScore = previous.Get("original_cvss_score");
        }
        else
        {
            var first = Sql.One(c, "SELECT severity, cvss_score FROM findings WHERE cve_id = @c ORDER BY (cvss_score IS NULL), id LIMIT 1", ("c", cveId));
            origSeverity = first?.Get("severity");
            origScore = first?.Get("cvss_score");
        }
        Sql.Exec(c,
            "INSERT INTO cve_rescores (cve_id, severity, cvss_score, reason, rescored_by, rescored_at, original_severity, original_cvss_score) " +
            "VALUES (@c, @sev, @score, @reason, @by, @at, @os, @oscore) " +
            "ON CONFLICT(cve_id) DO UPDATE SET severity=excluded.severity, cvss_score=excluded.cvss_score, " +
            "reason=excluded.reason, rescored_by=excluded.rescored_by, rescored_at=excluded.rescored_at",
            ("c", cveId), ("sev", severity), ("score", cvssScore), ("reason", reason), ("by", rescoredBy),
            ("at", Sql.UtcNow()), ("os", origSeverity), ("oscore", origScore));
        return GetRescore(c, cveId) ?? new Row();
    }

    public static Row? GetFindingAt(DbConnection c, string cveId, string branch, string specPath) =>
        Sql.One(c,
            "SELECT * FROM findings WHERE cve_id = @c AND COALESCE(branch, '') = @b AND COALESCE(spec_path, '') = @s ORDER BY id DESC LIMIT 1",
            ("c", cveId), ("b", branch), ("s", specPath));

    public static Row? GetFinding(DbConnection c, string cveId, string? package, string? specPath)
    {
        Row? row;
        if (!string.IsNullOrEmpty(specPath))
            row = Sql.One(c, "SELECT * FROM findings WHERE cve_id = @c AND spec_path = @s", ("c", cveId), ("s", specPath));
        else if (!string.IsNullOrEmpty(package))
            row = Sql.One(c, "SELECT * FROM findings WHERE cve_id = @c AND package_name = @p ORDER BY confidence DESC LIMIT 1", ("c", cveId), ("p", package));
        else
            row = Sql.One(c, "SELECT * FROM findings WHERE cve_id = @c ORDER BY confidence DESC LIMIT 1", ("c", cveId));
        return row is null ? null : HydrateFinding(row);
    }

    public static List<Row> FindingsForCve(DbConnection c, string cveId)
    {
        var rows = Sql.Query(c,
            $"SELECT * FROM findings WHERE cve_id = @c ORDER BY {StatusRank("")}, package_name, package_version",
            ("c", cveId));
        foreach (var r in rows) HydrateFinding(r);
        var rescore = GetRescore(c, cveId);
        if (rescore is not null) foreach (var r in rows) ApplyRescore(r, rescore);
        return rows;
    }

    // -- assignments ----------------------------------------------------------
    public static Row CreateAssignment(DbConnection c, string cveId, string packageName, string targetRepo, string notes, string assignee)
    {
        var now = Sql.UtcNow();
        Sql.Exec(c,
            "INSERT INTO assignments (cve_id, package_name, target_repo, status, notes, assignee_email, created_at, updated_at) " +
            "VALUES (@c, @p, @t, 'queued', @n, @a, @now, @now) " +
            "ON CONFLICT(cve_id, package_name) DO UPDATE SET status='queued', notes=excluded.notes, " +
            "updated_at=excluded.updated_at, target_repo=excluded.target_repo, assignee_email=excluded.assignee_email",
            ("c", cveId), ("p", packageName), ("t", targetRepo), ("n", notes), ("a", assignee), ("now", now));
        return Sql.One(c, "SELECT * FROM assignments WHERE cve_id = @c AND package_name = @p", ("c", cveId), ("p", packageName))!;
    }

    public static List<Row> ListAssignments(DbConnection c)
    {
        var rows = Sql.Query(c, "SELECT * FROM assignments ORDER BY created_at DESC");
        if (rows.Count == 0) return rows;
        var ps = new List<(string, object?)>();
        var ids = rows.Select(r => r.Get("id")!.ToString()!).ToList();
        // ids are integers; bind them as text and cast so one IN list works.
        var marks = Sql.InList("i", ids, ps);
        var comments = Sql.Query(c,
            $"SELECT * FROM assignment_comments WHERE assignment_id IN ({marks.Replace("@", "CAST(@").Replace(",", " AS INTEGER),") + " AS INTEGER)"}) ORDER BY id",
            ps.ToArray());
        var by = new Dictionary<long, List<Row>>();
        foreach (var cm in comments)
        {
            var aid = cm.Long("assignment_id");
            if (!by.TryGetValue(aid, out var list)) by[aid] = list = new();
            list.Add(cm);
        }
        foreach (var r in rows) r["comments"] = by.TryGetValue(r.Long("id"), out var l) ? l : new List<Row>();
        return rows;
    }

    public static Row? GetAssignment(DbConnection c, long id)
    {
        var row = Sql.One(c, "SELECT * FROM assignments WHERE id = @i", ("i", (int)id));
        if (row is null) return null;
        row["comments"] = Sql.Query(c, "SELECT * FROM assignment_comments WHERE assignment_id = @i ORDER BY id", ("i", (int)id));
        return row;
    }

    public static Row? AddComment(DbConnection c, long assignmentId, string body, string author)
    {
        var now = Sql.UtcNow();
        var id = Sql.Insert(c,
            "INSERT INTO assignment_comments (assignment_id, author, body, created_at) VALUES (@a, @au, @b, @now)",
            ("a", (int)assignmentId), ("au", author), ("b", body), ("now", now));
        Sql.Exec(c, "UPDATE assignments SET updated_at = @now WHERE id = @a", ("now", now), ("a", (int)assignmentId));
        return Sql.One(c, "SELECT * FROM assignment_comments WHERE id = @i", ("i", (int)id));
    }

    public static Row? UpdateAssignment(DbConnection c, long id, string status)
    {
        Sql.Exec(c, "UPDATE assignments SET status = @s, updated_at = @now WHERE id = @i",
            ("s", status), ("now", Sql.UtcNow()), ("i", (int)id));
        return Sql.One(c, "SELECT * FROM assignments WHERE id = @i", ("i", (int)id));
    }

    // -- finding triage -------------------------------------------------------
    public static Row? GetTriage(DbConnection c, string cveId, string branch, string specPath) =>
        Sql.One(c, "SELECT * FROM finding_triage WHERE cve_id = @c AND branch = @b AND spec_path = @s",
            ("c", cveId), ("b", branch ?? ""), ("s", specPath ?? ""));

    public static Dictionary<FindingKey, Row> TriageIndex(DbConnection c)
    {
        var index = new Dictionary<FindingKey, Row>();
        foreach (var row in Sql.Query(c, "SELECT * FROM finding_triage"))
            index[FindingKey.Of(row)] = row;
        return index;
    }

    public static Row UpsertTriage(DbConnection c, string cveId, string branch, string specPath,
        IDictionary<string, object?> fields) =>
        UpsertTriage(c, cveId, branch, specPath, fields.Select(kv => (kv.Key, kv.Value)));

    /// <summary>Create or partially update the triage record for one finding.</summary>
    public static Row UpsertTriage(DbConnection c, string cveId, string branch, string specPath,
        IEnumerable<(string Field, object? Value)> fields)
    {
        branch ??= ""; specPath ??= "";
        var updates = fields.Where(f => TriageFields.Contains(f.Field)).ToList();
        var now = Sql.UtcNow();
        if (GetTriage(c, cveId, branch, specPath) is null)
            Sql.Exec(c, "INSERT INTO finding_triage (cve_id, branch, spec_path, updated_at) VALUES (@c, @b, @s, @now)",
                ("c", cveId), ("b", branch), ("s", specPath), ("now", now));
        if (updates.Count > 0)
        {
            var ps = new List<(string, object?)>();
            var sets = new List<string>();
            for (var i = 0; i < updates.Count; i++)
            {
                sets.Add($"{updates[i].Field} = @v{i}");
                ps.Add(($"v{i}", updates[i].Value));
            }
            ps.Add(("now", now)); ps.Add(("c", cveId)); ps.Add(("b", branch)); ps.Add(("s", specPath));
            Sql.Exec(c,
                $"UPDATE finding_triage SET {string.Join(", ", sets)}, updated_at = @now WHERE cve_id = @c AND branch = @b AND spec_path = @s",
                ps.ToArray());
        }
        return GetTriage(c, cveId, branch, specPath) ?? new Row();
    }

    public static Row? AddFindingComment(DbConnection c, string cveId, string branch, string specPath, string body,
        string author = "admin", string kind = "comment")
    {
        var id = Sql.Insert(c,
            "INSERT INTO finding_comments (cve_id, branch, spec_path, kind, author, body, created_at) VALUES (@c, @b, @s, @k, @a, @body, @now)",
            ("c", cveId), ("b", branch ?? ""), ("s", specPath ?? ""), ("k", kind), ("a", author), ("body", body), ("now", Sql.UtcNow()));
        return Sql.One(c, "SELECT * FROM finding_comments WHERE id = @i", ("i", (int)id));
    }

    public static List<Row> FindingComments(DbConnection c, string cveId, string branch, string specPath) =>
        Sql.Query(c, "SELECT * FROM finding_comments WHERE cve_id = @c AND branch = @b AND spec_path = @s ORDER BY id",
            ("c", cveId), ("b", branch ?? ""), ("s", specPath ?? ""));

    // -- disputes -------------------------------------------------------------
    public static Row CreateDispute(DbConnection c, Row finding, string reason, string requestedBy,
        string firstUnaffectedVersion, bool neverApplicable, string status)
    {
        var now = Sql.UtcNow();
        var decidedBy = status != "pending" ? requestedBy : "";
        var id = Sql.Insert(c,
            "INSERT INTO disputes (cve_id, branch, spec_path, package_name, package_version, severity, reason, " +
            "first_unaffected_version, never_applicable, status, requested_by, requested_at, decided_by, decided_at) " +
            "VALUES (@c, @b, @s, @pn, @pv, @sev, @reason, @fuv, @na, @status, @rb, @now, @db, @da)",
            ("c", finding.Str("cve_id")), ("b", finding.Str("branch")), ("s", finding.Str("spec_path")),
            ("pn", finding.Get("package_name")), ("pv", finding.Get("package_version")), ("sev", finding.Get("severity")),
            ("reason", reason), ("fuv", firstUnaffectedVersion ?? ""), ("na", neverApplicable ? 1 : 0), ("status", status),
            ("rb", requestedBy), ("now", now), ("db", decidedBy), ("da", status != "pending" ? now : null));
        return GetDispute(c, id) ?? new Row();
    }

    public static Row? GetDispute(DbConnection c, long id) =>
        Sql.One(c, "SELECT * FROM disputes WHERE id = @i", ("i", (int)id));

    public static Row? PendingDispute(DbConnection c, string cveId, string branch, string specPath) =>
        Sql.One(c,
            "SELECT * FROM disputes WHERE cve_id = @c AND branch = @b AND spec_path = @s AND status = 'pending' ORDER BY id DESC LIMIT 1",
            ("c", cveId), ("b", branch ?? ""), ("s", specPath ?? ""));

    public static (List<Row> Rows, long Total) ListDisputes(DbConnection c, string status, string search, int limit, int offset)
    {
        var clauses = new List<string>();
        var ps = new List<(string, object?)>();
        if (status.Length > 0) { clauses.Add("status = @status"); ps.Add(("status", status)); }
        if (search.Length > 0)
        {
            clauses.Add("(cve_id ILIKE @like OR package_name ILIKE @like OR requested_by ILIKE @like OR reason ILIKE @like)");
            ps.Add(("like", $"%{search}%"));
        }
        var where = clauses.Count > 0 ? " WHERE " + string.Join(" AND ", clauses) : "";
        var total = Sql.Count(c, $"SELECT COUNT(*) FROM disputes{where}", ps.ToArray());
        var page = new List<(string, object?)>(ps) { ("lim", limit), ("off", offset) };
        return (Sql.Query(c, $"SELECT * FROM disputes{where} ORDER BY id DESC LIMIT @lim OFFSET @off", page.ToArray()), total);
    }

    public static Row DisputeCounts(DbConnection c)
    {
        var counts = new Row();
        foreach (var s in DisputeStatuses) counts[s] = 0L;
        foreach (var r in Sql.Query(c, "SELECT status, COUNT(*) AS c FROM disputes GROUP BY status"))
            counts[r.Str("status")] = r.Get("c");
        return counts;
    }

    public static Row? DecideDispute(DbConnection c, long id, string status, string decidedBy, string note)
    {
        var n = Sql.Exec(c,
            "UPDATE disputes SET status = @s, decided_by = @by, decided_at = @now, decision_note = @note WHERE id = @i AND status = 'pending'",
            ("s", status), ("by", decidedBy), ("now", Sql.UtcNow()), ("note", note), ("i", (int)id));
        return n > 0 ? GetDispute(c, id) : null;
    }

    public static Dictionary<FindingKey, Row> DisputeIndex(DbConnection c)
    {
        var index = new Dictionary<FindingKey, Row>();
        foreach (var r in Sql.Query(c, "SELECT id, cve_id, branch, spec_path, status FROM disputes ORDER BY id"))
            index[FindingKey.Of(r)] = new Row { ["id"] = r.Get("id"), ["status"] = r.Get("status") };
        return index;
    }

    // -- triage list ----------------------------------------------------------
    static readonly string[] FlatTriage =
    {
        "triage_status", "resolution_status", "final_verdict", "patch_link", "available_since",
        "github_pr_number", "github_pr_url", "github_pr_set_by", "github_pr_set_at", "owner", "vuln_id", "qualys_ids",
    };

    public static (List<Row> Rows, long Total) ListTriage(DbConnection c, string status, string search, int limit, int offset)
    {
        var clauses = new List<string>();
        var ps = new List<(string, object?)>();
        if (status.Length > 0) { clauses.Add("f.status = @status"); ps.Add(("status", status)); }
        if (search.Length > 0)
        {
            clauses.Add("(f.cve_id ILIKE @like OR f.package_name ILIKE @like)");
            ps.Add(("like", $"%{search}%"));
        }
        var where = clauses.Count > 0 ? " WHERE " + string.Join(" AND ", clauses) : "";
        var total = Sql.Count(c, $"SELECT COUNT(*) FROM findings f{where}", ps.ToArray());
        var page = new List<(string, object?)>(ps) { ("lim", limit), ("off", offset) };
        var rows = Sql.Query(c,
            $@"SELECT f.*, t.id AS triage_id, t.triage_status, t.resolution_status,
                      t.final_verdict, t.patch_link, t.available_since,
                      t.github_pr_number, t.github_pr_url, t.github_pr_set_by,
                      t.github_pr_set_at, t.owner, t.vuln_id, t.qualys_ids
               FROM findings f
               LEFT JOIN finding_triage t
                 ON t.cve_id = f.cve_id AND t.branch = f.branch AND t.spec_path = f.spec_path
               {where}
               ORDER BY (t.updated_at IS NULL), t.updated_at DESC, f.cve_id
               LIMIT @lim OFFSET @off",
            page.ToArray());
        var comments = CommentsByFinding(c, rows.Select(FindingKey.Of));
        foreach (var row in rows)
        {
            HydrateFinding(row);
            Row? record = null;
            var triageId = row.Get("triage_id");
            row.Remove("triage_id");
            if (triageId is not null)
            {
                record = new Row
                {
                    ["cve_id"] = row.Get("cve_id"),
                    ["branch"] = row.Get("branch"),
                    ["spec_path"] = row.Get("spec_path"),
                    ["comments"] = new List<Row>(),
                };
                foreach (var key in FlatTriage)
                {
                    var v = row.Get(key);
                    row.Remove(key);
                    record[key] = v is null or "" ? "" : v;
                }
                record["comments"] = comments.TryGetValue(FindingKey.Of(row), out var l) ? l : new List<Row>();
            }
            else
            {
                foreach (var key in FlatTriage) row.Remove(key);
            }
            row["triage"] = record;
            row["comments"] = record is not null ? record["comments"] : new List<Row>();
        }
        return (rows, total);
    }

    public static Dictionary<FindingKey, List<Row>> CommentsByFinding(DbConnection c, IEnumerable<FindingKey> keys)
    {
        var list = keys.Distinct().ToList();
        var outp = new Dictionary<FindingKey, List<Row>>();
        if (list.Count == 0) return outp;
        var ps = new List<(string, object?)>();
        var parts = new List<string>();
        for (var i = 0; i < list.Count; i++)
        {
            parts.Add($"(cve_id = @c{i} AND branch = @b{i} AND spec_path = @s{i})");
            ps.Add(($"c{i}", list[i].CveId)); ps.Add(($"b{i}", list[i].Branch)); ps.Add(($"s{i}", list[i].SpecPath));
        }
        foreach (var row in Sql.Query(c, $"SELECT * FROM finding_comments WHERE {string.Join(" OR ", parts)} ORDER BY id", ps.ToArray()))
        {
            var key = FindingKey.Of(row);
            if (!outp.TryGetValue(key, out var l)) outp[key] = l = new();
            l.Add(row);
        }
        return outp;
    }

    // -- automation requests --------------------------------------------------
    public const int StaleRunningHours = 3;

    static Row AutomationRow(Row r)
    {
        r["cve_ids"] = Sql.Loads(r.Get("cve_ids"), EmptyList) is List<object?> l ? l : EmptyList();
        return r;
    }

    public static Row CreateAutomationRequest(DbConnection c, string packageName, string branch, string specPath,
        List<string> cveIds, string mode, string prNumber, string requestedBy)
    {
        var id = Sql.Insert(c,
            "INSERT INTO automation_requests (package_name, branch, spec_path, cve_ids, mode, pr_number, status, requested_by, requested_at) " +
            "VALUES (@p, @b, @s, @cves, @mode, @pr, 'queued', @by, @now)",
            ("p", packageName), ("b", branch ?? ""), ("s", specPath ?? ""), ("cves", JsonSerializer.Serialize(cveIds)),
            ("mode", mode), ("pr", prNumber ?? ""), ("by", requestedBy), ("now", Sql.UtcNow()));
        return AutomationRow(Sql.One(c, "SELECT * FROM automation_requests WHERE id = @i", ("i", (int)id))!);
    }

    public static List<Row> ListAutomationRequests(DbConnection c) =>
        Sql.Query(c, "SELECT * FROM automation_requests ORDER BY id DESC").Select(AutomationRow).ToList();

    public static Row? ClaimAutomationRequest(DbConnection c)
    {
        var stale = DateTime.UtcNow.AddHours(-StaleRunningHours).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff", System.Globalization.CultureInfo.InvariantCulture) + "+00:00";
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var row = Sql.One(c,
                "SELECT id FROM automation_requests WHERE status = 'queued' OR (status = 'running' AND COALESCE(started_at, '') < @stale) ORDER BY id LIMIT 1",
                ("stale", stale));
            if (row is null) return null;
            var id = (int)row.Long("id");
            var n = Sql.Exec(c,
                "UPDATE automation_requests SET status = 'running', started_at = @now WHERE id = @i " +
                "AND (status = 'queued' OR (status = 'running' AND COALESCE(started_at, '') < @stale))",
                ("now", Sql.UtcNow()), ("i", id), ("stale", stale));
            if (n == 1)
                return AutomationRow(Sql.One(c, "SELECT * FROM automation_requests WHERE id = @i", ("i", id))!);
        }
        return null;
    }

    public static Row? FinishAutomationRequest(DbConnection c, long id, string status, string message,
        string prUrl, string prNumber, string branchName)
    {
        Sql.Exec(c,
            "UPDATE automation_requests SET status = @s, message = @m, pr_url = @u, " +
            "pr_number = CASE WHEN @n != '' THEN @n ELSE pr_number END, branch_name = @bn, finished_at = @now WHERE id = @i",
            ("s", status), ("m", message), ("u", prUrl), ("n", prNumber), ("bn", branchName), ("now", Sql.UtcNow()), ("i", (int)id));
        var row = Sql.One(c, "SELECT * FROM automation_requests WHERE id = @i", ("i", (int)id));
        return row is null ? null : AutomationRow(row);
    }

    // -- CVE enrichment cache -------------------------------------------------
    public static void CacheCve(DbConnection c, string cveId, Row payload) =>
        Sql.Exec(c,
            "INSERT INTO cve_cache (cve_id, payload, fetched_at) VALUES (@c, @p, @now) " +
            "ON CONFLICT(cve_id) DO UPDATE SET payload=excluded.payload, fetched_at=excluded.fetched_at",
            ("c", cveId), ("p", JsonSerializer.Serialize(payload)), ("now", Sql.UtcNow()));

    public static Row? GetCachedCve(DbConnection c, string cveId)
    {
        var row = Sql.One(c, "SELECT * FROM cve_cache WHERE cve_id = @c", ("c", cveId));
        if (row is null) return null;
        var payload = Sql.Loads(row.Get("payload"), () => new Row()) as Row ?? new Row();
        payload["_fetched_at"] = row.Get("fetched_at");
        return payload;
    }
}
