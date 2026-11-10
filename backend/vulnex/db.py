"""Persistence layer: SQLite by default, PostgreSQL when ``DATABASE_URL`` is set.

Both run the same SQL (``pgcompat`` translates the few dialect differences); the
Postgres schema is managed by Alembic (``backend/migrations``), the SQLite schema
by ``SCHEMA`` below.

The dashboard tables (``packages``, ``patches``, ``findings``) hold the *current*
scan snapshot and are replaced atomically on every scan. ``scans`` keeps a run
history, ``assignments`` persists the triage queue, and ``cve_cache`` stores
enriched CVE records fetched on demand.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from . import config, pgcompat

_BACKEND_DIR = Path(__file__).resolve().parents[1]
_migrated: set[str] = set()

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    branches TEXT,
    ecosystem TEXT,
    package_count INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    affected_count INTEGER DEFAULT 0,
    patched_count INTEGER DEFAULT 0,
    false_positive_count INTEGER DEFAULT 0,
    unconfirmed_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'running',
    message TEXT,
    duration_seconds REAL
);

CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    branch TEXT,
    name TEXT,
    version TEXT,
    release TEXT,
    epoch INTEGER DEFAULT 0,
    evr TEXT,
    summary TEXT,
    license TEXT,
    url TEXT,
    group_name TEXT,
    spec_path TEXT,
    spec_url TEXT,
    source0_url TEXT,
    source_urls TEXT,
    tarball_name TEXT,
    tarball_url TEXT,
    tarball_available INTEGER,
    patch_count INTEGER DEFAULT 0,
    is_primary INTEGER DEFAULT 1,
    UNIQUE(branch, spec_path)
);

CREATE TABLE IF NOT EXISTS patches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    package_name TEXT,
    branch TEXT,
    spec_path TEXT,
    tag TEXT,
    filename TEXT,
    cve_ids TEXT,
    is_nopatch INTEGER DEFAULT 0,
    file_present INTEGER,
    status TEXT,
    comment TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    cve_id TEXT,
    package_name TEXT,
    package_version TEXT,
    branch TEXT,
    spec_path TEXT,
    status TEXT,
    severity TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    confidence REAL,
    description TEXT,
    fixed_version TEXT,
    advisory_id TEXT,
    source TEXT,
    refs TEXT,
    upstream_fix TEXT,
    patch_name TEXT,
    patch_status TEXT,
    fixed_in TEXT,
    fixed_in_basis TEXT,
    fix_source TEXT,
    first_seen TEXT,
    affected_files TEXT,
    corroborating_sources TEXT,
    evidence TEXT,
    raw_sources TEXT,
    UNIQUE(cve_id, branch, spec_path)
);

CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT,
    package_name TEXT,
    target_repo TEXT,
    status TEXT DEFAULT 'queued',
    notes TEXT,
    assignee_email TEXT DEFAULT '',
    created_at TEXT,
    updated_at TEXT,
    UNIQUE(cve_id, package_name)
);

CREATE TABLE IF NOT EXISTS assignment_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL,
    author TEXT,
    body TEXT NOT NULL,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS finding_triage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    branch TEXT NOT NULL DEFAULT '',
    spec_path TEXT NOT NULL DEFAULT '',
    package_name TEXT,
    triage_status TEXT DEFAULT 'open',
    resolution_status TEXT DEFAULT '',
    final_verdict TEXT DEFAULT '',
    patch_link TEXT DEFAULT '',
    available_since TEXT DEFAULT '',
    github_pr_number TEXT DEFAULT '',
    github_pr_url TEXT DEFAULT '',
    github_pr_set_by TEXT DEFAULT '',
    github_pr_set_at TEXT,
    owner TEXT DEFAULT '',
    vuln_id TEXT DEFAULT '',
    qualys_ids TEXT DEFAULT '',
    updated_at TEXT,
    UNIQUE(cve_id, branch, spec_path)
);

-- Human triage trail for a finding: ordinary comments plus 'dispute' entries,
-- where the dispute reason is what shows up underneath the triage comment.
CREATE TABLE IF NOT EXISTS finding_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    branch TEXT NOT NULL DEFAULT '',
    spec_path TEXT NOT NULL DEFAULT '',
    kind TEXT DEFAULT 'comment',
    author TEXT,
    body TEXT NOT NULL,
    created_at TEXT
);

-- Dispute requests. A developer raises one (pending); the administrator approves or
-- rejects it. Approving marks the finding's resolution status as disputed.
CREATE TABLE IF NOT EXISTS disputes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    branch TEXT NOT NULL DEFAULT '',
    spec_path TEXT NOT NULL DEFAULT '',
    package_name TEXT,
    package_version TEXT,
    severity TEXT,
    reason TEXT NOT NULL,
    first_unaffected_version TEXT DEFAULT '',
    never_applicable INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT,
    requested_at TEXT,
    decided_by TEXT DEFAULT '',
    decided_at TEXT,
    decision_note TEXT DEFAULT ''
);

-- An administrator's own severity and CVSS score for a CVE. It overrides the scanned
-- value everywhere it is shown and is never overwritten by a scan.
CREATE TABLE IF NOT EXISTS cve_rescores (
    cve_id TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    cvss_score REAL,
    reason TEXT NOT NULL,
    rescored_by TEXT,
    rescored_at TEXT,
    original_severity TEXT,
    original_cvss_score REAL
);

-- A request to automate one package's fix: the ticked CVEs go into one pull request,
-- either a new one or an existing one. The automation picks queued rows up.
CREATE TABLE IF NOT EXISTS automation_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    branch TEXT NOT NULL DEFAULT '',
    spec_path TEXT NOT NULL DEFAULT '',
    cve_ids TEXT NOT NULL,
    mode TEXT NOT NULL,
    pr_number TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'queued',
    requested_by TEXT,
    requested_at TEXT,
    started_at TEXT,
    finished_at TEXT,
    pr_url TEXT DEFAULT '',
    branch_name TEXT DEFAULT '',
    message TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id TEXT PRIMARY KEY,
    payload TEXT,
    fetched_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_package ON findings(package_name);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_patches_package ON patches(package_name);
CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
CREATE INDEX IF NOT EXISTS idx_findings_spec ON findings(branch, spec_path);
CREATE INDEX IF NOT EXISTS idx_comments_assignment ON assignment_comments(assignment_id);
CREATE INDEX IF NOT EXISTS idx_triage_key ON finding_triage(cve_id, branch, spec_path);
CREATE INDEX IF NOT EXISTS idx_finding_comments_key ON finding_comments(cve_id, branch, spec_path);
CREATE INDEX IF NOT EXISTS idx_disputes_status ON disputes(status);
CREATE INDEX IF NOT EXISTS idx_disputes_key ON disputes(cve_id, branch, spec_path);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str | Path | None = None):
    """Open the configured database.

    An explicit ``path`` always means that SQLite file (CLI ``--db``, tests, the
    static export). Without one, ``DATABASE_URL`` selects PostgreSQL.
    """
    if path is None and config.DATABASE_URL:
        return pgcompat.connect(config.DATABASE_URL)
    db_path = Path(path or config.DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def migrate_postgres(url: str | None = None) -> None:
    """Bring the PostgreSQL schema to the latest Alembic revision (idempotent)."""
    from alembic import command
    from alembic.config import Config

    url = url or config.DATABASE_URL
    if url in _migrated:
        return
    cfg = Config(str(_BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_DIR / "migrations"))
    cfg.set_main_option("prepend_sys_path", str(_BACKEND_DIR))
    cfg.attributes["url"] = url
    command.upgrade(cfg, "head")
    _migrated.add(url)


def init_db(conn) -> None:
    if getattr(conn, "dialect", "") == "postgres":
        migrate_postgres()
        return
    conn.executescript(SCHEMA)
    # Lightweight in-place migration for existing free-tier SQLite deployments.
    assignment_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(assignments)").fetchall()
    }
    if "assignee_email" not in assignment_columns:
        conn.execute("ALTER TABLE assignments ADD COLUMN assignee_email TEXT DEFAULT ''")
    finding_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(findings)").fetchall()
    }
    for column in ("fixed_in", "fixed_in_basis", "fix_source", "first_seen"):
        if column not in finding_columns:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {column} TEXT")
    request_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(automation_requests)").fetchall()
    }
    for column in ("started_at", "finished_at", "pr_url", "branch_name", "message"):
        if column not in request_columns:
            conn.execute(f"ALTER TABLE automation_requests ADD COLUMN {column} TEXT DEFAULT ''")
    conn.commit()


@contextmanager
def session(path: str | Path | None = None) -> Iterator[sqlite3.Connection]:
    conn = connect(path)
    try:
        init_db(conn)
        yield conn
    finally:
        conn.close()


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def loads(value: str | None, default: Any = None) -> Any:
    if value is None:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


# -- writes -----------------------------------------------------------------
def start_scan(conn: sqlite3.Connection, branches: list[str], ecosystem: str) -> int:
    cur = conn.execute(
        "INSERT INTO scans (started_at, branches, ecosystem, status) VALUES (?, ?, ?, 'running')",
        (utcnow(), ",".join(branches), ecosystem),
    )
    conn.commit()
    return int(cur.lastrowid)


def finish_scan(
    conn: sqlite3.Connection,
    scan_id: int,
    *,
    status: str,
    message: str = "",
    counts: dict[str, int] | None = None,
    duration: float | None = None,
) -> None:
    counts = counts or {}
    conn.execute(
        """
        UPDATE scans SET finished_at=?, status=?, message=?, package_count=?,
            finding_count=?, affected_count=?, patched_count=?,
            false_positive_count=?, unconfirmed_count=?, duration_seconds=?
        WHERE id=?
        """,
        (
            utcnow(),
            status,
            message,
            counts.get("packages", 0),
            counts.get("findings", 0),
            counts.get("affected", 0),
            counts.get("patched", 0),
            counts.get("false_positive", 0),
            counts.get("unconfirmed", 0),
            duration,
            scan_id,
        ),
    )
    conn.commit()


def _first_seen_index(conn: sqlite3.Connection) -> dict[tuple[str, str, str], str]:
    """When each CVE + branch + spec was first scanned, from the snapshot about to be replaced."""
    rows = conn.execute(
        "SELECT cve_id, COALESCE(branch, '') AS b, COALESCE(spec_path, '') AS s, first_seen "
        "FROM findings WHERE first_seen IS NOT NULL"
    ).fetchall()
    return {(r["cve_id"], r["b"], r["s"]): r["first_seen"] for r in rows}


def replace_snapshot(
    conn: sqlite3.Connection,
    scan_id: int,
    packages: Iterable[dict],
    patches: Iterable[dict],
    findings: Iterable[dict],
    branches: list[str] | None = None,
) -> None:
    """Replace only the scanned stable branches while retaining other stable data.

    Legacy development/fasttrack rows are always purged. A scan of 4.0 must not
    erase the already-scanned 3.0 snapshot (and vice versa).
    """
    # A scan replaces every finding, so remember when each one was first seen before the
    # old rows go. A finding that is new in this scan starts at this scan's start time.
    seen = _first_seen_index(conn)
    started = conn.execute("SELECT started_at FROM scans WHERE id = ?", (scan_id,)).fetchone()
    scanned_at = (started["started_at"] if started else None) or utcnow()
    if branches:
        placeholders = ",".join("?" for _ in branches)
        for table in ("packages", "patches", "findings"):
            conn.execute(
                f"DELETE FROM {table} WHERE branch IN ({placeholders}) "
                "OR branch NOT IN ('3.0', '4.0') OR branch IS NULL",
                tuple(branches),
            )
    else:
        # Backward-compatible full replacement for callers that explicitly
        # provide no branch scope (e.g. legacy tests and maintenance tasks).
        for table in ("packages", "patches", "findings"):
            conn.execute(f"DELETE FROM {table}")

    conn.executemany(
        """
        INSERT INTO packages (scan_id, branch, name, version, release, epoch, evr,
            summary, license, url, group_name, spec_path, spec_url, source0_url,
            source_urls, tarball_name, tarball_url, tarball_available, patch_count,
            is_primary)
        VALUES (:scan_id, :branch, :name, :version, :release, :epoch, :evr,
            :summary, :license, :url, :group_name, :spec_path, :spec_url,
            :source0_url, :source_urls, :tarball_name, :tarball_url,
            :tarball_available, :patch_count, :is_primary)
        """,
        packages,
    )
    conn.executemany(
        """
        INSERT INTO patches (scan_id, package_name, branch, spec_path, tag, filename,
            cve_ids, is_nopatch, file_present, status, comment)
        VALUES (:scan_id, :package_name, :branch, :spec_path, :tag, :filename,
            :cve_ids, :is_nopatch, :file_present, :status, :comment)
        """,
        patches,
    )
    # Rows built before the fix-provenance columns existed omit them.
    findings = [
        {"fixed_in": None, "fixed_in_basis": None, "fix_source": None, **row}
        for row in findings
    ]
    for row in findings:
        key = (row["cve_id"], row.get("branch") or "", row.get("spec_path") or "")
        row["first_seen"] = row.get("first_seen") or seen.get(key) or scanned_at
    conn.executemany(
        """
        INSERT INTO findings (scan_id, cve_id, package_name, package_version, branch,
            spec_path, status, severity, cvss_score, cvss_vector, confidence,
            description, fixed_version, advisory_id, source, refs, upstream_fix,
            patch_name, patch_status, fixed_in, fixed_in_basis, fix_source, first_seen,
            affected_files, corroborating_sources, evidence, raw_sources)
        VALUES (:scan_id, :cve_id, :package_name, :package_version, :branch,
            :spec_path, :status, :severity, :cvss_score, :cvss_vector, :confidence,
            :description, :fixed_version, :advisory_id, :source, :refs, :upstream_fix,
            :patch_name, :patch_status, :fixed_in, :fixed_in_basis, :fix_source, :first_seen,
            :affected_files, :corroborating_sources, :evidence, :raw_sources)
        """,
        findings,
    )
    conn.commit()


# -- reads ------------------------------------------------------------------
def latest_scan(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else None


def scan_history(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# A rescored CVE counts under the administrator's severity, not the scanned one.
_EFFECTIVE_SEVERITY = (
    "COALESCE((SELECT r.severity FROM cve_rescores r WHERE r.cve_id = findings.cve_id), severity)"
)


def stats(conn: sqlite3.Connection, branch: str | None = None) -> dict:
    """Return dashboard counts scoped to the selected stable branch, if any."""
    if branch not in (None, "", "3.0", "4.0"):
        raise ValueError("Stats can only be scoped to stable branch 3.0 or 4.0")

    branch_clause = " AND branch = ?" if branch else ""
    branch_params = (branch,) if branch else ()
    packages = conn.execute(
        "SELECT COUNT(*) c FROM packages" + (" WHERE branch = ?" if branch else ""),
        branch_params,
    ).fetchone()["c"]
    total = conn.execute(
        "SELECT COUNT(*) c FROM findings" + (" WHERE branch = ?" if branch else ""),
        branch_params,
    ).fetchone()["c"]

    def count(*where: str, table: str = "findings") -> int:
        clauses = list(where)
        params: tuple = ()
        if branch:
            clauses.append("branch = ?")
            params = (branch,)
        sql = f"SELECT COUNT(*) c FROM {table}"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        return conn.execute(sql, params).fetchone()["c"]

    # The site's subject is open exposures only; severity and CVE counts are
    # restricted to the selected stable branch when a branch filter is present.
    open_where = f"status = '{config.OPEN_STATUS}'"
    open_total = count(open_where)
    severity = {
        s: count(f"{open_where} AND {_EFFECTIVE_SEVERITY} = '{s}'")
        for s in ("critical", "high", "medium", "low", "none", "unknown")
    }
    if branch:
        scan = next(
            (
                item for item in scan_history(conn, limit=100)
                if branch in (item.get("branches") or "").split(",")
                and item.get("status") == "success"
            ),
            {},
        )
    else:
        scan = latest_scan(conn) or {}
    distinct_where = open_where + branch_clause
    distinct_params = branch_params
    return {
        "total_packages": packages,
        "total_findings": open_total,
        "affected": open_total,
        "severity": severity,
        "distinct_cves": conn.execute(
            f"SELECT COUNT(DISTINCT cve_id) c FROM findings WHERE {distinct_where}",
            distinct_params,
        ).fetchone()["c"],
        "patched": count("status = 'patched'"),
        "false_positive": count("status = 'false_positive'"),
        "unconfirmed": count("status = 'unconfirmed'"),
        "excluded_findings": total - open_total,
        "total_patches": count(table="patches"),
        "nopatch_markers": count("is_nopatch = 1", table="patches"),
        "last_scan": scan,
        "assignments": conn.execute("SELECT COUNT(*) c FROM assignments").fetchone()["c"],
    }


def _rows(conn: sqlite3.Connection, sql: str, params: Iterable = ()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]


def list_packages(
    conn: sqlite3.Connection,
    search: str = "",
    branch: str = "",
    limit: int = 50,
    offset: int = 0,
    branches: list[str] | None = None,
) -> tuple[list[dict], int]:
    clauses, params = [], []
    if search:
        clauses.append("name LIKE ?")
        params.append(f"%{search}%")
    if branches:
        placeholders = ",".join("?" for _ in branches)
        clauses.append(f"branch IN ({placeholders})")
        params.extend(branches)
    elif branch:
        clauses.append("branch = ?")
        params.append(branch)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    total = conn.execute(f"SELECT COUNT(*) c FROM packages{where}", tuple(params)).fetchone()["c"]
    rows = _rows(
        conn,
        f"SELECT * FROM packages{where} ORDER BY name, version LIMIT ? OFFSET ?",
        [*params, limit, offset],
    )

    # Attach finding counts per (branch, spec) in a single grouped query: the
    # same spec_path exists on every branch, and several .spec files can share
    # one package name, so (branch, spec_path) is the package identity.
    counts_by_spec: dict[tuple[str, str], dict[str, int]] = {}
    spec_paths = sorted({r["spec_path"] for r in rows if r.get("spec_path")})
    if spec_paths:
        placeholders = ",".join("?" for _ in spec_paths)
        grouped = conn.execute(
            f"""
            SELECT branch, spec_path, status, COUNT(*) c FROM findings
            WHERE spec_path IN ({placeholders}) AND status = ?
            GROUP BY branch, spec_path, status
            """,
            (*spec_paths, config.OPEN_STATUS),
        ).fetchall()
        for g in grouped:
            key = (g["branch"], g["spec_path"])
            counts_by_spec.setdefault(key, {})[g["status"]] = g["c"]

    for row in rows:
        row["source_urls"] = loads(row.get("source_urls"), [])
        row["finding_counts"] = counts_by_spec.get(
            (row.get("branch"), row.get("spec_path")), {}
        )
    return rows, total


def get_package(
    conn: sqlite3.Connection,
    name: str,
    branch: str | None = None,
    spec_path: str | None = None,
) -> dict | None:
    """Fetch a package snapshot.

    ``spec_path`` is the true identity (a package name such as ``golang`` can be
    built from several versioned spec files). When it is not supplied we fall
    back to the primary spec for the name, then the newest versioned spec.
    """
    if spec_path and branch:
        row = conn.execute(
            "SELECT * FROM packages WHERE spec_path = ? AND branch = ?",
            (spec_path, branch),
        ).fetchone()
    elif spec_path:
        row = conn.execute(
            "SELECT * FROM packages WHERE spec_path = ? "
            "ORDER BY is_primary DESC, id LIMIT 1",
            (spec_path,),
        ).fetchone()
    elif branch:
        row = conn.execute(
            "SELECT * FROM packages WHERE name = ? AND branch = ? "
            "ORDER BY is_primary DESC, id LIMIT 1",
            (name, branch),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM packages WHERE name = ? "
            "ORDER BY is_primary DESC, branch, id LIMIT 1",
            (name,),
        ).fetchone()
    if not row:
        return None
    pkg = dict(row)
    pkg["source_urls"] = loads(pkg.get("source_urls"), [])
    pkg["patches"] = _rows(
        conn,
        "SELECT * FROM patches WHERE branch = ? AND spec_path = ? ORDER BY id",
        (pkg["branch"], pkg["spec_path"]),
    )
    for p in pkg["patches"]:
        p["cve_ids"] = loads(p.get("cve_ids"), [])
    pkg["findings"] = _rows(
        conn,
        "SELECT * FROM findings WHERE branch = ? AND spec_path = ? "
        "ORDER BY severity, cve_id",
        (pkg["branch"], pkg["spec_path"]),
    )
    for f in pkg["findings"]:
        _hydrate_finding(f)
    # Surface sibling specs that share this package name (e.g. golang-1.24.spec).
    pkg["variants"] = _rows(
        conn,
        "SELECT branch, spec_path, version, release, evr, is_primary FROM packages "
        "WHERE name = ? ORDER BY is_primary DESC, branch, version",
        (pkg["name"],),
    )
    return pkg


# "100% patched": the spec applies the CVE's patch file AND its %changelog names the
# fix. Such findings need no further analysis once the fix is recorded elsewhere.
CONFIRMED_PATCHED_SQL = (
    "status = 'patched' AND fix_source = 'patch' "
    "AND fixed_in_basis = 'changelog' AND patch_status = 'applied'"
)

# Open work first: exposed packages, then ones needing a human look, then the rest.
_STATUS_RANK = (
    "CASE {p}status WHEN 'affected' THEN 0 WHEN 'unconfirmed' THEN 1 "
    "WHEN 'patched' THEN 2 WHEN 'false_positive' THEN 3 ELSE 4 END"
)


def list_findings(
    conn: sqlite3.Connection,
    status: str = "",
    severity: str = "",
    search: str = "",
    package: str = "",
    branch: str = "",
    limit: int = 100,
    offset: int = 0,
    branches: list[str] | None = None,
    triage_status: str = "",
    resolution_status: str = "",
    owner: str = "",
    fixed_version: str = "",
) -> tuple[list[dict], int]:
    """Findings page + total. Workflow filters are applied in SQL, before paging."""
    clauses, params = [], []
    if status:
        clauses.append("f.status = ?")
        params.append(status)
    if severity:
        clauses.append("COALESCE(rs.severity, f.severity) = ?")
        params.append(severity)
    if package:
        clauses.append("f.package_name = ?")
        params.append(package)
    if branches:
        placeholders = ",".join("?" for _ in branches)
        clauses.append(f"f.branch IN ({placeholders})")
        params.extend(branches)
    elif branch:
        clauses.append("f.branch = ?")
        params.append(branch)
    if search:
        clauses.append(
            "(f.cve_id LIKE ? OR f.package_name LIKE ? OR f.description LIKE ? OR f.advisory_id LIKE ?)"
        )
        like = f"%{search}%"
        params.extend([like, like, like, like])

    # Triage columns live in a second table (one row per cve+branch+spec), so join
    # it only when a workflow filter needs it. A missing row counts as "open".
    join = " LEFT JOIN cve_rescores rs ON rs.cve_id = f.cve_id"
    if triage_status or resolution_status or owner:
        join += (
            " LEFT JOIN finding_triage t ON t.cve_id = f.cve_id"
            " AND t.branch = COALESCE(f.branch, '') AND t.spec_path = COALESCE(f.spec_path, '')"
        )
    if triage_status:
        clauses.append("LOWER(COALESCE(NULLIF(t.triage_status, ''), 'open')) = ?")
        params.append(triage_status.lower())
    if resolution_status:
        clauses.append("LOWER(COALESCE(NULLIF(t.resolution_status, ''), f.status, '')) = ?")
        params.append(resolution_status.lower())
    if owner:
        clauses.append("LOWER(COALESCE(t.owner, '')) LIKE ?")
        params.append(f"%{owner.lower()}%")
    if fixed_version:
        # Only patched findings have an azurelinux-test fix release.
        clauses.append("f.status = 'patched' AND LOWER(COALESCE(f.fixed_in, '')) LIKE ?")
        params.append(f"%{fixed_version.lower()}%")

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    total = conn.execute(
        f"SELECT COUNT(*) c FROM findings f{join}{where}", tuple(params)
    ).fetchone()["c"]
    rank = _STATUS_RANK.format(p="f.")
    sev = (
        "CASE COALESCE(rs.severity, f.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'none' THEN 4 ELSE 5 END"
    )
    # A CVE sorts by its most urgent package, so a CVE that is still affected anywhere
    # leads the list. Among affected CVEs the most recently scanned come first, then by
    # severity. All rows of one CVE stay together (cve_id comes before any per-row
    # column) with affected packages first inside it.
    order = (
        f"cve_rank, cve_new DESC, cve_sev, f.cve_id, {rank}, "
        "COALESCE(f.first_seen, '') DESC, f.confidence DESC, f.package_name"
    )
    rows = _rows(
        conn,
        "SELECT f.*, rs.severity AS rs_severity, rs.cvss_score AS rs_score, rs.reason AS rs_reason, "
        "rs.rescored_by AS rs_by, rs.rescored_at AS rs_at, "
        f"MIN({rank}) OVER (PARTITION BY f.cve_id) AS cve_rank, "
        f"MIN({sev}) OVER (PARTITION BY f.cve_id) AS cve_sev, "
        f"MAX(CASE WHEN {rank} = 0 THEN COALESCE(f.first_seen, '') ELSE '' END) "
        "OVER (PARTITION BY f.cve_id) AS cve_new "
        f"FROM findings f{join}{where} ORDER BY {order} LIMIT ? OFFSET ?",
        [*params, limit, offset],
    )
    for f in rows:
        f.pop("cve_rank", None)
        f.pop("cve_sev", None)
        f.pop("cve_new", None)
    for f in rows:
        _hydrate_finding(f)
        severity_o, score_o, reason, by, at = (f.pop(k, None) for k in ("rs_severity", "rs_score", "rs_reason", "rs_by", "rs_at"))
        if severity_o:
            _apply_rescore(f, {"severity": severity_o, "cvss_score": score_o, "reason": reason,
                               "rescored_by": by, "rescored_at": at})
    return rows, total


def _apply_rescore(f: dict, rescore: dict) -> dict:
    """Show the administrator's severity and score on a finding, keeping the scanned ones."""
    f["scanned_severity"] = f.get("severity")
    f["scanned_cvss_score"] = f.get("cvss_score")
    f["severity"] = rescore["severity"]
    f["cvss_score"] = rescore.get("cvss_score")
    f["rescore"] = {
        "severity": rescore["severity"],
        "cvss_score": rescore.get("cvss_score"),
        "reason": rescore.get("reason") or "",
        "rescored_by": rescore.get("rescored_by") or "",
        "rescored_at": rescore.get("rescored_at") or "",
    }
    return f


def get_rescore(conn: sqlite3.Connection, cve_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM cve_rescores WHERE cve_id = ?", (cve_id,)).fetchone()
    return dict(row) if row else None


def set_rescore(
    conn: sqlite3.Connection, cve_id: str, severity: str, cvss_score: float | None,
    reason: str, rescored_by: str,
) -> dict:
    """Record (or replace) the administrator's score. The first scanned values are kept once."""
    previous = get_rescore(conn, cve_id)
    if previous:
        original_severity, original_score = previous["original_severity"], previous["original_cvss_score"]
    else:
        first = conn.execute(
            "SELECT severity, cvss_score FROM findings WHERE cve_id = ? "
            "ORDER BY (cvss_score IS NULL), id LIMIT 1", (cve_id,)
        ).fetchone()
        original_severity = first["severity"] if first else None
        original_score = first["cvss_score"] if first else None
    conn.execute(
        """
        INSERT INTO cve_rescores (cve_id, severity, cvss_score, reason, rescored_by, rescored_at,
                                  original_severity, original_cvss_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET severity=excluded.severity, cvss_score=excluded.cvss_score,
            reason=excluded.reason, rescored_by=excluded.rescored_by, rescored_at=excluded.rescored_at
        """,
        (cve_id, severity, cvss_score, reason, rescored_by, utcnow(), original_severity, original_score),
    )
    conn.commit()
    return get_rescore(conn, cve_id) or {}


def _hydrate_finding(f: dict) -> dict:
    f["references"] = loads(f.pop("refs", None), [])
    f["affected_files"] = loads(f.get("affected_files"), [])
    f["corroborating_sources"] = loads(f.get("corroborating_sources"), [])
    f["evidence"] = loads(f.get("evidence"), [])
    f["raw_sources"] = loads(f.get("raw_sources"), [])
    return f


def get_finding_at(
    conn: sqlite3.Connection, cve_id: str, branch: str = "", spec_path: str = ""
) -> dict | None:
    """The finding at an exact CVE + branch + spec path (as stored on triage records)."""
    row = conn.execute(
        "SELECT * FROM findings WHERE cve_id = ? AND COALESCE(branch, '') = ? "
        "AND COALESCE(spec_path, '') = ? ORDER BY id DESC LIMIT 1",
        (cve_id, branch or "", spec_path or ""),
    ).fetchone()
    return dict(row) if row else None


def get_finding(
    conn: sqlite3.Connection,
    cve_id: str,
    package: str | None = None,
    spec_path: str | None = None,
) -> dict | None:
    if spec_path:
        row = conn.execute(
            "SELECT * FROM findings WHERE cve_id = ? AND spec_path = ?",
            (cve_id, spec_path),
        ).fetchone()
    elif package:
        row = conn.execute(
            "SELECT * FROM findings WHERE cve_id = ? AND package_name = ? "
            "ORDER BY confidence DESC LIMIT 1",
            (cve_id, package),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM findings WHERE cve_id = ? ORDER BY confidence DESC LIMIT 1",
            (cve_id,),
        ).fetchone()
    if not row:
        return None
    return _hydrate_finding(dict(row))


def findings_for_cve(conn: sqlite3.Connection, cve_id: str) -> list[dict]:
    rows = [
        _hydrate_finding(dict(r))
        for r in conn.execute(
            f"SELECT * FROM findings WHERE cve_id = ? ORDER BY {_STATUS_RANK.format(p='')}, "
            "package_name, package_version", (cve_id,)
        ).fetchall()
    ]
    rescore = get_rescore(conn, cve_id)
    if rescore:
        for row in rows:
            _apply_rescore(row, rescore)
    return rows


def get_patch(
    conn: sqlite3.Connection,
    package: str,
    tag: str,
    branch: str,
    spec_path: str | None = None,
) -> dict | None:
    if spec_path:
        if branch:
            row = conn.execute(
                "SELECT * FROM patches WHERE spec_path = ? AND tag = ? AND branch = ?",
                (spec_path, tag, branch),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM patches WHERE spec_path = ? AND tag = ?",
                (spec_path, tag),
            ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM patches WHERE package_name = ? AND tag = ? AND branch = ?",
            (package, tag, branch),
        ).fetchone()
    if not row:
        return None
    patch = dict(row)
    patch["cve_ids"] = loads(patch.get("cve_ids"), [])
    return patch


# -- assignments ------------------------------------------------------------
def create_assignment(
    conn: sqlite3.Connection,
    cve_id: str,
    package_name: str,
    target_repo: str,
    notes: str = "",
    assignee_email: str = "",
) -> dict:
    now = utcnow()
    conn.execute(
        """
        INSERT INTO assignments (cve_id, package_name, target_repo, status, notes, assignee_email, created_at, updated_at)
        VALUES (?, ?, ?, 'queued', ?, ?, ?, ?)
        ON CONFLICT(cve_id, package_name) DO UPDATE SET
            status='queued', notes=excluded.notes, updated_at=excluded.updated_at,
            target_repo=excluded.target_repo, assignee_email=excluded.assignee_email
        """,
        (cve_id, package_name, target_repo, notes, assignee_email, now, now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM assignments WHERE cve_id = ? AND package_name = ?",
        (cve_id, package_name),
    ).fetchone()
    return dict(row)


def list_assignments(conn: sqlite3.Connection) -> list[dict]:
    """Queue rows with their triage comments attached in one grouped query."""
    rows = _rows(conn, "SELECT * FROM assignments ORDER BY created_at DESC")
    if not rows:
        return rows
    ids = [r["id"] for r in rows]
    marks = ",".join("?" * len(ids))
    by_assignment: dict[int, list[dict]] = {}
    for c in _rows(
        conn,
        f"SELECT * FROM assignment_comments WHERE assignment_id IN ({marks}) ORDER BY id",
        ids,
    ):
        by_assignment.setdefault(c["assignment_id"], []).append(c)
    for r in rows:
        r["comments"] = by_assignment.get(r["id"], [])
    return rows


def get_assignment(conn: sqlite3.Connection, assignment_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM assignments WHERE id = ?", (assignment_id,)).fetchone()
    if not row:
        return None
    record = dict(row)
    record["comments"] = _rows(
        conn,
        "SELECT * FROM assignment_comments WHERE assignment_id = ? ORDER BY id",
        (assignment_id,),
    )
    return record


def add_comment(
    conn: sqlite3.Connection,
    assignment_id: int,
    body: str,
    author: str = "editor",
) -> dict | None:
    """Append an editor triage comment to a queued assignment."""
    now = utcnow()
    cursor = conn.execute(
        "INSERT INTO assignment_comments (assignment_id, author, body, created_at) "
        "VALUES (?, ?, ?, ?)",
        (assignment_id, author, body, now),
    )
    conn.execute("UPDATE assignments SET updated_at = ? WHERE id = ?", (now, assignment_id))
    conn.commit()
    row = conn.execute(
        "SELECT * FROM assignment_comments WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return dict(row) if row else None


def comments_for(conn: sqlite3.Connection, assignment_id: int) -> list[dict]:
    return _rows(
        conn,
        "SELECT * FROM assignment_comments WHERE assignment_id = ? ORDER BY id",
        (assignment_id,),
    )


def update_assignment(conn: sqlite3.Connection, assignment_id: int, status: str) -> dict | None:
    conn.execute(
        "UPDATE assignments SET status = ?, updated_at = ? WHERE id = ?",
        (status, utcnow(), assignment_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM assignments WHERE id = ?", (assignment_id,)).fetchone()
    return dict(row) if row else None


# -- finding triage ---------------------------------------------------------
# Triage is keyed by the finding identity: (cve_id, branch, spec_path). It holds
# the human verdict/patch call, the GitHub PR reference and the triage trail.
_TRIAGE_FIELDS = (
    "package_name",
    "triage_status",
    "resolution_status",
    "final_verdict",
    "patch_link",
    "available_since",
    "github_pr_number",
    "github_pr_url",
    "github_pr_set_by",
    "github_pr_set_at",
    "owner",
    "vuln_id",
    "qualys_ids",
)


def get_triage(
    conn: sqlite3.Connection, cve_id: str, branch: str = "", spec_path: str = ""
) -> dict | None:
    row = conn.execute(
        "SELECT * FROM finding_triage WHERE cve_id = ? AND branch = ? AND spec_path = ?",
        (cve_id, branch or "", spec_path or ""),
    ).fetchone()
    return dict(row) if row else None


def triage_index(conn) -> dict[tuple[str, str, str], dict]:
    """Every triage record keyed by (cve_id, branch, spec_path), in ONE query.

    Looking records up one finding at a time costs a database round trip each;
    against a remote database a 4,500-row list then needs minutes. The triage table
    only holds what people typed in, so reading it whole is cheap.
    """
    return {
        (row["cve_id"], row["branch"] or "", row["spec_path"] or ""): row
        for row in _rows(conn, "SELECT * FROM finding_triage")
    }


def upsert_triage(
    conn: sqlite3.Connection,
    cve_id: str,
    branch: str,
    spec_path: str,
    **fields: Any,
) -> dict:
    """Create or partially update the triage record for one finding."""
    cve_id, branch, spec_path = cve_id, branch or "", spec_path or ""
    updates = {k: v for k, v in fields.items() if k in _TRIAGE_FIELDS}
    now = utcnow()
    if not get_triage(conn, cve_id, branch, spec_path):
        conn.execute(
            "INSERT INTO finding_triage (cve_id, branch, spec_path, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (cve_id, branch, spec_path, now),
        )
    if updates:
        assignments = ", ".join(f"{k} = ?" for k in updates)
        conn.execute(
            f"UPDATE finding_triage SET {assignments}, updated_at = ? "
            "WHERE cve_id = ? AND branch = ? AND spec_path = ?",
            (*updates.values(), now, cve_id, branch, spec_path),
        )
    conn.commit()
    return get_triage(conn, cve_id, branch, spec_path) or {}


def add_finding_comment(
    conn: sqlite3.Connection,
    cve_id: str,
    branch: str,
    spec_path: str,
    body: str,
    author: str = "admin",
    kind: str = "comment",
) -> dict | None:
    """Append a triage comment (or a ``dispute`` entry) to a finding."""
    cursor = conn.execute(
        "INSERT INTO finding_comments (cve_id, branch, spec_path, kind, author, body, "
        "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (cve_id, branch or "", spec_path or "", kind, author, body, utcnow()),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM finding_comments WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return dict(row) if row else None


def finding_comments(
    conn: sqlite3.Connection, cve_id: str, branch: str = "", spec_path: str = ""
) -> list[dict]:
    return _rows(
        conn,
        "SELECT * FROM finding_comments WHERE cve_id = ? AND branch = ? AND spec_path = ? "
        "ORDER BY id",
        (cve_id, branch or "", spec_path or ""),
    )


# -- disputes ---------------------------------------------------------------
DISPUTE_STATUSES = ("pending", "approved", "rejected")


def create_dispute(
    conn: sqlite3.Connection,
    finding: dict,
    reason: str,
    requested_by: str,
    first_unaffected_version: str = "",
    never_applicable: bool = False,
    status: str = "pending",
) -> dict:
    """Record a dispute request for one finding (its package details are copied in)."""
    now = utcnow()
    decided_by = requested_by if status != "pending" else ""
    cursor = conn.execute(
        "INSERT INTO disputes (cve_id, branch, spec_path, package_name, package_version, "
        "severity, reason, first_unaffected_version, never_applicable, status, requested_by, "
        "requested_at, decided_by, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            finding["cve_id"], finding.get("branch") or "", finding.get("spec_path") or "",
            finding.get("package_name"), finding.get("package_version"), finding.get("severity"),
            reason, first_unaffected_version or "", 1 if never_applicable else 0, status,
            requested_by, now, decided_by, now if status != "pending" else None,
        ),
    )
    conn.commit()
    return get_dispute(conn, cursor.lastrowid) or {}


def create_automation_request(
    conn: sqlite3.Connection,
    package_name: str,
    branch: str,
    spec_path: str,
    cve_ids: list[str],
    mode: str,
    pr_number: str,
    requested_by: str,
) -> dict:
    cursor = conn.execute(
        "INSERT INTO automation_requests (package_name, branch, spec_path, cve_ids, mode, "
        "pr_number, status, requested_by, requested_at) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)",
        (package_name, branch or "", spec_path or "", json.dumps(cve_ids), mode, pr_number or "",
         requested_by, utcnow()),
    )
    conn.commit()
    return _automation_row(conn.execute(
        "SELECT * FROM automation_requests WHERE id = ?", (cursor.lastrowid,)).fetchone())


def _automation_row(row) -> dict:
    record = dict(row)
    try:
        record["cve_ids"] = json.loads(record.get("cve_ids") or "[]")
    except ValueError:
        record["cve_ids"] = []
    return record


def list_automation_requests(conn: sqlite3.Connection) -> list[dict]:
    """Every request, newest first (the table stays small: one row per button press)."""
    return [_automation_row(r) for r in conn.execute(
        "SELECT * FROM automation_requests ORDER BY id DESC").fetchall()]


STALE_RUNNING_HOURS = 3


def claim_automation_request(conn: sqlite3.Connection) -> dict | None:
    """Take the oldest queued request (or one stuck 'running' for hours) and mark it running."""
    from datetime import datetime, timedelta, timezone

    stale = (datetime.now(timezone.utc) - timedelta(hours=STALE_RUNNING_HOURS)).isoformat()
    for _ in range(3):
        row = conn.execute(
            "SELECT id FROM automation_requests WHERE status = 'queued' "
            "OR (status = 'running' AND COALESCE(started_at, '') < ?) ORDER BY id LIMIT 1",
            (stale,),
        ).fetchone()
        if not row:
            return None
        cursor = conn.execute(
            "UPDATE automation_requests SET status = 'running', started_at = ? WHERE id = ? "
            "AND (status = 'queued' OR (status = 'running' AND COALESCE(started_at, '') < ?))",
            (utcnow(), row["id"], stale),
        )
        conn.commit()
        if cursor.rowcount == 1:  # nobody else claimed it first
            return _automation_row(conn.execute(
                "SELECT * FROM automation_requests WHERE id = ?", (row["id"],)).fetchone())
    return None


def finish_automation_request(
    conn: sqlite3.Connection, request_id: int, status: str, message: str = "",
    pr_url: str = "", pr_number: str = "", branch_name: str = "",
) -> dict | None:
    conn.execute(
        "UPDATE automation_requests SET status = ?, message = ?, pr_url = ?, "
        "pr_number = CASE WHEN ? != '' THEN ? ELSE pr_number END, branch_name = ?, finished_at = ? "
        "WHERE id = ?",
        (status, message, pr_url, pr_number, pr_number, branch_name, utcnow(), request_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM automation_requests WHERE id = ?", (request_id,)).fetchone()
    return _automation_row(row) if row else None


def get_dispute(conn: sqlite3.Connection, dispute_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM disputes WHERE id = ?", (dispute_id,)).fetchone()
    return dict(row) if row else None


def pending_dispute(conn: sqlite3.Connection, cve_id: str, branch: str, spec_path: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM disputes WHERE cve_id = ? AND branch = ? AND spec_path = ? "
        "AND status = 'pending' ORDER BY id DESC LIMIT 1",
        (cve_id, branch or "", spec_path or ""),
    ).fetchone()
    return dict(row) if row else None


def list_disputes(
    conn: sqlite3.Connection,
    status: str = "",
    search: str = "",
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Disputes, newest first; ``status`` is one of pending/approved/rejected (empty = all)."""
    clauses, params = [], []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if search:
        clauses.append("(cve_id LIKE ? OR package_name LIKE ? OR requested_by LIKE ? OR reason LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like, like])
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    total = conn.execute(f"SELECT COUNT(*) c FROM disputes{where}", tuple(params)).fetchone()["c"]
    rows = _rows(
        conn,
        f"SELECT * FROM disputes{where} ORDER BY id DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    )
    return rows, total


def dispute_counts(conn: sqlite3.Connection) -> dict[str, int]:
    counts = {s: 0 for s in DISPUTE_STATUSES}
    for row in conn.execute("SELECT status, COUNT(*) c FROM disputes GROUP BY status").fetchall():
        counts[row["status"]] = row["c"]
    return counts


def decide_dispute(
    conn: sqlite3.Connection, dispute_id: int, status: str, decided_by: str, note: str = ""
) -> dict | None:
    """Approve or reject a *pending* dispute. Returns None when it is not pending."""
    cursor = conn.execute(
        "UPDATE disputes SET status = ?, decided_by = ?, decided_at = ?, decision_note = ? "
        "WHERE id = ? AND status = 'pending'",
        (status, decided_by, utcnow(), note, dispute_id),
    )
    conn.commit()
    return get_dispute(conn, dispute_id) if cursor.rowcount else None


def dispute_index(conn: sqlite3.Connection) -> dict[tuple[str, str, str], dict]:
    """The newest dispute for every finding, in one query (id, status only)."""
    index: dict[tuple[str, str, str], dict] = {}
    for row in conn.execute(
        "SELECT id, cve_id, branch, spec_path, status FROM disputes ORDER BY id"
    ).fetchall():
        index[(row["cve_id"], row["branch"] or "", row["spec_path"] or "")] = {
            "id": row["id"], "status": row["status"],
        }
    return index


def comments_by_finding(
    conn: sqlite3.Connection, keys: Iterable[tuple[str, str, str]]
) -> dict[tuple[str, str, str], list[dict]]:
    """Group comments for many findings in one query."""
    keys = list(keys)
    if not keys:
        return {}
    clauses = " OR ".join(
        "(cve_id = ? AND branch = ? AND spec_path = ?)" for _ in keys
    )
    params: list[Any] = [
        value for key in keys for value in (key[0], key[1] or "", key[2] or "")
    ]
    out: dict[tuple[str, str, str], list[dict]] = {}
    for row in _rows(
        conn, f"SELECT * FROM finding_comments WHERE {clauses} ORDER BY id", params
    ):
        out.setdefault(
            (row["cve_id"], row["branch"] or "", row["spec_path"] or ""), []
        ).append(row)
    return out


def list_triage(
    conn: sqlite3.Connection,
    status: str = "affected",
    search: str = "",
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Findings joined with their triage record, newest triage activity first.

    ``status`` filters on the *finding* status; pass ``""`` for every finding.
    """
    clauses, params = [], []
    if status:
        clauses.append("f.status = ?")
        params.append(status)
    if search:
        clauses.append("(f.cve_id LIKE ? OR f.package_name LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    total = conn.execute(
        f"SELECT COUNT(*) c FROM findings f{where}", tuple(params)
    ).fetchone()["c"]
    rows = _rows(
        conn,
        f"""
        SELECT f.*, t.id AS triage_id, t.triage_status, t.resolution_status,
               t.final_verdict, t.patch_link, t.available_since,
               t.github_pr_number, t.github_pr_url, t.github_pr_set_by,
               t.github_pr_set_at, t.owner, t.vuln_id, t.qualys_ids
        FROM findings f
        LEFT JOIN finding_triage t
          ON t.cve_id = f.cve_id AND t.branch = f.branch AND t.spec_path = f.spec_path
        {where}
        ORDER BY (t.updated_at IS NULL), t.updated_at DESC, f.cve_id
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    )
    _FLAT = (
        "triage_status", "resolution_status", "final_verdict", "patch_link",
        "available_since", "github_pr_number", "github_pr_url", "github_pr_set_by",
        "github_pr_set_at", "owner", "vuln_id", "qualys_ids",
    )
    comments = comments_by_finding(
        conn, [(r["cve_id"], r["branch"], r["spec_path"]) for r in rows]
    )
    for row in rows:
        _hydrate_finding(row)
        record = None
        if row.pop("triage_id", None):
            record = {
                "cve_id": row["cve_id"],
                "branch": row["branch"],
                "spec_path": row["spec_path"],
                "comments": [],
            }
            for key in _FLAT:
                record[key] = row.pop(key, None) or ""
        else:
            for key in _FLAT:
                row.pop(key, None)
        if record is not None:
            record["comments"] = comments.get(
                (row["cve_id"], row["branch"] or "", row["spec_path"] or ""), []
            )
        row["triage"] = record
        row["comments"] = record["comments"] if record else []
    return rows, total


def all_triage_records(conn: sqlite3.Connection) -> list[dict]:
    """Every triage record with its trail, for the static export."""
    rows = _rows(conn, "SELECT * FROM finding_triage ORDER BY id DESC")
    comments = comments_by_finding(
        conn, [(r["cve_id"], r["branch"], r["spec_path"]) for r in rows]
    )
    for row in rows:
        row["comments"] = comments.get(
            (row["cve_id"], row["branch"] or "", row["spec_path"] or ""), []
        )
    return rows


# -- CVE enrichment cache ---------------------------------------------------
def cache_cve(conn: sqlite3.Connection, cve_id: str, payload: dict) -> None:
    conn.execute(
        """
        INSERT INTO cve_cache (cve_id, payload, fetched_at) VALUES (?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET payload=excluded.payload, fetched_at=excluded.fetched_at
        """,
        (cve_id, dumps(payload), utcnow()),
    )
    conn.commit()


def get_cached_cve(conn: sqlite3.Connection, cve_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM cve_cache WHERE cve_id = ?", (cve_id,)).fetchone()
    if not row:
        return None
    payload = loads(row["payload"], {})
    payload["_fetched_at"] = row["fetched_at"]
    return payload


def set_scan_message(conn: sqlite3.Connection, scan_id: int, message: str) -> None:
    conn.execute("UPDATE scans SET message = ? WHERE id = ?", (message, scan_id))
    conn.commit()
