"""Read-only check that every row in the database is valid for BOTH backends.

Run it against any database (it only SELECTs, inside a read-only transaction):

    DATABASE_URL=postgresql://... python scripts/check_shared_data.py

It checks what the Python code relies on when it reads rows written by the .NET API
(and the reverse): timestamps are ISO-8601, JSON-in-text columns parse to the expected
type, and status columns hold only known values. Exit code 0 = clean, 1 = problems.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

TIMESTAMP_COLUMN = re.compile(r"(_at|^first_seen|^time)$")

# column -> the JSON type it must parse to
JSON_COLUMNS = {
    ("patches", "cve_ids"): list,
    ("packages", "source_urls"): list,
    ("findings", "references"): list,
    ("findings", "affected_files"): list,
    ("findings", "corroborating_sources"): list,
    ("findings", "evidence"): list,
    ("findings", "raw_sources"): list,
    ("automation_requests", "cve_ids"): list,
    ("cve_cache", "payload"): dict,
}

ALLOWED = {
    ("findings", "status"): {"affected", "patched", "false_positive", "unconfirmed"},
    ("disputes", "status"): {"pending", "approved", "rejected"},
    ("automation_requests", "status"): {"queued", "running", "done", "partial", "failed"},
    ("automation_requests", "mode"): {"new_pr", "existing_pr"},
}


def _is_iso(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def check(conn) -> list[str]:
    problems: list[str] = []
    tables = [r[0] for r in conn.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'").fetchall()]
    for table in sorted(tables):
        if table == "alembic_version":
            continue
        cols = {r[0]: r[1] for r in conn.execute(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = ?", (table,)).fetchall()}
        wanted = [c for c in cols if TIMESTAMP_COLUMN.search(c) and cols[c] == "text"]
        wanted += [c for (t, c) in {**JSON_COLUMNS, **ALLOWED} if t == table and c in cols]
        if not wanted:
            continue
        for row in conn.execute(f"SELECT * FROM {table}").fetchall():
            ident = row["id"] if "id" in row.keys() else "?"
            for col in dict.fromkeys(wanted):
                value = row[col]
                if value is None or value == "":
                    continue
                where = f"{table}.{col} (id={ident})"
                if TIMESTAMP_COLUMN.search(col) and cols[col] == "text" and not _is_iso(str(value)):
                    problems.append(f"{where}: not an ISO timestamp: {str(value)[:40]!r}")
                expected = JSON_COLUMNS.get((table, col))
                if expected is not None:
                    try:
                        if not isinstance(json.loads(value), expected):
                            problems.append(f"{where}: JSON is not a {expected.__name__}")
                    except (TypeError, ValueError):
                        problems.append(f"{where}: not valid JSON: {str(value)[:40]!r}")
                allowed = ALLOWED.get((table, col))
                if allowed is not None and value not in allowed:
                    problems.append(f"{where}: unexpected value {value!r}")
    return problems


def main() -> int:
    from vulnex import config, db

    if not config.DATABASE_URL:
        print("Set DATABASE_URL to the PostgreSQL database to check.", file=sys.stderr)
        return 2
    conn = db.connect()
    try:
        conn.execute("SET TRANSACTION READ ONLY")
        problems = check(conn)
    finally:
        conn.rollback()
        conn.close()
    if problems:
        print(f"{len(problems)} problem(s):")
        for p in problems[:50]:
            print("  -", p)
        return 1
    print("OK: all timestamps, JSON columns and status values are valid for both backends.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
