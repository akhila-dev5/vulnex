"""Copy a SQLite snapshot (``data/vulnex.db``) into PostgreSQL.

Two uses:

* one-time move of an existing deployment to Supabase (``--only all``), and
* the scheduled scan, which still produces the SQLite snapshot and then refreshes
  only the *scan* tables in Postgres (``--only snapshot``).

The triage tables (comments, disputes, PR links, assignments) are the data people
typed in, so they are never overwritten implicitly: a non-empty target table is
left alone unless ``force`` is passed.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

SNAPSHOT_TABLES = ("scans", "packages", "patches", "findings")
TRIAGE_TABLES = (
    "assignments",
    "assignment_comments",
    "finding_triage",
    "finding_comments",
    "cve_cache",
)
# Tables with a serial ``id`` whose sequence must follow the imported ids.
_SERIAL = set(SNAPSHOT_TABLES) | {
    "assignments", "assignment_comments", "finding_triage", "finding_comments",
}
_BATCH = 1000


def _sqlite_columns(src: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in src.execute(f"PRAGMA table_info({table})").fetchall()]


def _pg_columns(pg, table: str) -> list[str]:
    rows = pg.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = ? ORDER BY ordinal_position",
        (table,),
    ).fetchall()
    return [r["column_name"] for r in rows]


def copy_table(src: sqlite3.Connection, pg, table: str) -> int:
    """Replace ``table`` in Postgres with the SQLite rows; returns the row count."""
    shared = [c for c in _sqlite_columns(src, table) if c in set(_pg_columns(pg, table))]
    if not shared:
        return 0
    pg.execute(f"DELETE FROM {table}")
    cols = ", ".join(shared)
    marks = ", ".join(f":{c}" for c in shared)
    count = 0
    cursor = src.execute(f"SELECT {cols} FROM {table}")
    while True:
        chunk = cursor.fetchmany(_BATCH)
        if not chunk:
            break
        pg.executemany(
            f"INSERT INTO {table} ({cols}) VALUES ({marks})",
            [dict(zip(shared, row)) for row in chunk],
        )
        count += len(chunk)
    if table in _SERIAL:
        pg.execute(
            f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
            f"COALESCE((SELECT MAX(id) FROM {table}), 1), "
            f"(SELECT COUNT(*) > 0 FROM {table}))"
        )
    return count


def _row_count(pg, table: str) -> int:
    return int(pg.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"])


def import_sqlite(
    sqlite_path: str | Path, pg, only: str = "all", force: bool = False
) -> dict[str, Any]:
    """Import ``sqlite_path`` into the Postgres connection ``pg`` in one transaction."""
    if only not in ("all", "snapshot", "triage"):
        raise ValueError("only must be 'all', 'snapshot' or 'triage'")
    path = Path(sqlite_path)
    if not path.is_file():
        raise FileNotFoundError(f"SQLite database not found: {path}")
    src = sqlite3.connect(str(path))
    result: dict[str, Any] = {"copied": {}, "skipped": {}}
    try:
        tables: list[str] = []
        if only in ("all", "snapshot"):
            tables += list(SNAPSHOT_TABLES)
        if only in ("all", "triage"):
            tables += list(TRIAGE_TABLES)
        try:
            for table in tables:
                if table in TRIAGE_TABLES and not force and _row_count(pg, table):
                    result["skipped"][table] = "target already has rows (use force to overwrite)"
                    continue
                result["copied"][table] = copy_table(src, pg, table)
            pg.commit()
        except Exception:
            pg.rollback()
            raise
    finally:
        src.close()
    return result


def seed_if_empty(pg, sqlite_path: str | Path) -> dict[str, Any]:
    """Load the bundled snapshot into a Postgres that has never had a scan.

    A brand-new Supabase database has the tables (Alembic creates them) but no
    rows, so the dashboard would show no CVEs until someone ran the import by
    hand. The scan snapshot ships in the repo (``data/vulnex.db``), so the first
    start loads it. Anything already in the database is left alone: once a scan
    exists this does nothing, and triage tables are never overwritten.
    """
    if int(pg.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]):
        return {"seeded": False, "reason": "database already has scans"}
    if not Path(sqlite_path).is_file():
        return {"seeded": False, "reason": f"no snapshot file at {sqlite_path}"}
    result = import_sqlite(sqlite_path, pg, only="all")
    result["seeded"] = bool(result["copied"].get("findings"))
    return result
