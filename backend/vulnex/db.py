"""SQLite persistence layer.

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

from . import config

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
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    db_path = Path(path or config.DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
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


def replace_snapshot(
    conn: sqlite3.Connection,
    scan_id: int,
    packages: Iterable[dict],
    patches: Iterable[dict],
    findings: Iterable[dict],
) -> None:
    """Atomically swap the current dashboard snapshot."""
    conn.execute("DELETE FROM packages")
    conn.execute("DELETE FROM patches")
    conn.execute("DELETE FROM findings")

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
    conn.executemany(
        """
        INSERT INTO findings (scan_id, cve_id, package_name, package_version, branch,
            spec_path, status, severity, cvss_score, cvss_vector, confidence,
            description, fixed_version, advisory_id, source, refs, upstream_fix,
            patch_name, patch_status, affected_files, corroborating_sources, evidence,
            raw_sources)
        VALUES (:scan_id, :cve_id, :package_name, :package_version, :branch,
            :spec_path, :status, :severity, :cvss_score, :cvss_vector, :confidence,
            :description, :fixed_version, :advisory_id, :source, :refs, :upstream_fix,
            :patch_name, :patch_status, :affected_files, :corroborating_sources, :evidence,
            :raw_sources)
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


def stats(conn: sqlite3.Connection) -> dict:
    packages = conn.execute("SELECT COUNT(*) c FROM packages").fetchone()["c"]
    total = conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]

    def count(*where: str) -> int:
        base = "SELECT COUNT(*) c FROM findings"
        if where:
            base += " WHERE " + " AND ".join(where)
        return conn.execute(base).fetchone()["c"]

    severity = {
        s: count(f"severity = '{s}'")
        for s in ("critical", "high", "medium", "low", "none", "unknown")
    }
    scan = latest_scan(conn) or {}
    return {
        "total_packages": packages,
        "total_findings": total,
        "affected": count("status = 'affected'"),
        "patched": count("status = 'patched'"),
        "false_positive": count("status = 'false_positive'"),
        "unconfirmed": count("status = 'unconfirmed'"),
        "severity": severity,
        "distinct_cves": conn.execute(
            "SELECT COUNT(DISTINCT cve_id) c FROM findings"
        ).fetchone()["c"],
        "total_patches": conn.execute("SELECT COUNT(*) c FROM patches").fetchone()["c"],
        "nopatch_markers": conn.execute(
            "SELECT COUNT(*) c FROM patches WHERE is_nopatch = 1"
        ).fetchone()["c"],
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
) -> tuple[list[dict], int]:
    clauses, params = [], []
    if search:
        clauses.append("name LIKE ?")
        params.append(f"%{search}%")
    if branch:
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
            WHERE spec_path IN ({placeholders})
            GROUP BY branch, spec_path, status
            """,
            tuple(spec_paths),
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


def list_findings(
    conn: sqlite3.Connection,
    status: str = "",
    severity: str = "",
    search: str = "",
    package: str = "",
    branch: str = "",
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    clauses, params = [], []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if package:
        clauses.append("package_name = ?")
        params.append(package)
    if branch:
        clauses.append("branch = ?")
        params.append(branch)
    if search:
        clauses.append(
            "(cve_id LIKE ? OR package_name LIKE ? OR description LIKE ? OR advisory_id LIKE ?)"
        )
        like = f"%{search}%"
        params.extend([like, like, like, like])
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    total = conn.execute(f"SELECT COUNT(*) c FROM findings{where}", tuple(params)).fetchone()["c"]
    order = (
        "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        "WHEN 'low' THEN 3 WHEN 'none' THEN 4 ELSE 5 END, confidence DESC, cve_id"
    )
    rows = _rows(
        conn,
        f"SELECT * FROM findings{where} ORDER BY {order} LIMIT ? OFFSET ?",
        [*params, limit, offset],
    )
    for f in rows:
        _hydrate_finding(f)
    return rows, total


def _hydrate_finding(f: dict) -> dict:
    f["references"] = loads(f.pop("refs", None), [])
    f["affected_files"] = loads(f.get("affected_files"), [])
    f["corroborating_sources"] = loads(f.get("corroborating_sources"), [])
    f["evidence"] = loads(f.get("evidence"), [])
    f["raw_sources"] = loads(f.get("raw_sources"), [])
    return f


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
    return [
        _hydrate_finding(dict(r))
        for r in conn.execute(
            "SELECT * FROM findings WHERE cve_id = ? ORDER BY package_name", (cve_id,)
        ).fetchall()
    ]


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
) -> dict:
    now = utcnow()
    conn.execute(
        """
        INSERT INTO assignments (cve_id, package_name, target_repo, status, notes, created_at, updated_at)
        VALUES (?, ?, ?, 'queued', ?, ?, ?)
        ON CONFLICT(cve_id, package_name) DO UPDATE SET
            status='queued', notes=excluded.notes, updated_at=excluded.updated_at,
            target_repo=excluded.target_repo
        """,
        (cve_id, package_name, target_repo, notes, now, now),
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
