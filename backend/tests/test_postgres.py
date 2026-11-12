"""PostgreSQL support.

The translation tests always run. The integration tests need a real database:
``VULNEX_TEST_DATABASE_URL=postgresql://... pytest tests/test_postgres.py``
(they are skipped otherwise, and CI provides one).
"""

import os
import sqlite3

import pytest

from vulnex import config, db
from vulnex.pgcompat import Row, normalize_url, translate
from vulnex.sqlite_import import import_sqlite

PG_URL = os.environ.get("VULNEX_TEST_DATABASE_URL", "")
needs_pg = pytest.mark.skipif(not PG_URL, reason="VULNEX_TEST_DATABASE_URL not set")


# -- always on -------------------------------------------------------------------
def test_placeholders_like_and_percent_are_translated():
    assert translate("SELECT 1 WHERE a = ? AND b LIKE ?") == "SELECT 1 WHERE a = %s AND b ILIKE %s"
    assert translate("WHERE c LIKE 'x%'") == "WHERE c ILIKE 'x%%'"
    assert translate("VALUES (:a, :b)", named=True) == "VALUES (%(a)s, %(b)s)"


def test_urls_are_normalised():
    assert normalize_url("postgres://u:p@db.abc.supabase.co:5432/postgres").endswith("?sslmode=require")
    assert normalize_url("postgresql://u@h/db?application_name=x").endswith("&sslmode=require")
    assert "sslmode" not in normalize_url("postgresql://u@localhost/db")
    assert normalize_url("postgresql://u@h/db?sslmode=disable").count("sslmode") == 1


def test_rows_read_by_name_index_and_dict():
    row = Row(["id", "name"], [7, "x"])
    assert (row["id"], row[1], dict(row)) == (7, "x", {"id": 7, "name": "x"})


def test_sqlite_is_used_without_database_url(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_URL", "")
    conn = db.connect(tmp_path / "a.db")
    assert isinstance(conn, sqlite3.Connection)
    conn.close()


def test_explicit_path_wins_over_database_url(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_URL", "postgresql://never-used/db")
    conn = db.connect(tmp_path / "b.db")
    assert isinstance(conn, sqlite3.Connection)
    conn.close()


# -- real PostgreSQL ---------------------------------------------------------------
@pytest.fixture()
def pg():
    conn = db.connect()  # conftest points DATABASE_URL at the test database
    yield conn
    conn.close()


def _columns_sqlite() -> dict[str, set[str]]:
    mem = sqlite3.connect(":memory:")
    mem.executescript(db.SCHEMA)
    out = {}
    for (table,) in mem.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ):
        out[table] = {r[1] for r in mem.execute(f"PRAGMA table_info({table})")}
    return out


@needs_pg
def test_postgres_schema_matches_the_sqlite_schema(pg):
    got: dict[str, set[str]] = {}
    for r in pg.execute(
        "SELECT table_name, column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name <> 'alembic_version'"
    ).fetchall():
        got.setdefault(r["table_name"], set()).add(r["column_name"])
    assert got == _columns_sqlite()


@needs_pg
def test_row_level_security_hides_tables_from_the_public_api(pg):
    rows = pg.execute(
        "SELECT relname, relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND c.relkind = 'r' AND relname <> 'alembic_version'"
    ).fetchall()
    assert rows and all(r["relrowsecurity"] for r in rows)


@needs_pg
def test_migrations_are_idempotent(pg):
    db._migrated.clear()
    db.init_db(pg)
    db.init_db(pg)
    # The latest migration in the repo, not a fixed number, so adding a migration never breaks this.
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config(str(db._BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(db._BACKEND_DIR / "migrations"))
    head = ScriptDirectory.from_config(cfg).get_current_head()
    assert pg.execute("SELECT version_num FROM alembic_version").fetchone()["version_num"] == head


@needs_pg
def test_triage_survives_a_new_connection_and_a_scan_refresh(pg):
    key = ("CVE-2024-0500", "3.0", "SPECS/demo/demo.spec")
    db.upsert_triage(pg, *key, package_name="demo", github_pr_number="19015",
                     github_pr_url="https://github.com/o/r/pull/19015", github_pr_set_by="a@b.c")
    db.add_finding_comment(pg, *key, kind="dispute", author="a@b.c", body="UPSTREAM: not affected")
    pg.close()

    # A "redeploy": brand-new connection, then a full scan snapshot replacement.
    again = db.connect()
    scan = db.start_scan(again, ["3.0"], "Azure Linux:3")
    db.replace_snapshot(again, scan, [], [], [], branches=["3.0"])
    triage = db.get_triage(again, *key)
    comments = db.finding_comments(again, *key)
    again.close()
    assert triage["github_pr_number"] == "19015"
    assert [c["kind"] for c in comments] == ["dispute"]


@needs_pg
def test_search_is_case_insensitive_like_sqlite(pg):
    scan = db.start_scan(pg, ["3.0"], "Azure Linux:3")
    row = {c: None for c in (
        "package_version", "spec_path", "severity", "cvss_score", "cvss_vector", "confidence",
        "description", "fixed_version", "advisory_id", "source", "refs", "upstream_fix",
        "patch_name", "patch_status", "fixed_in", "fixed_in_basis", "fix_source",
        "affected_files", "corroborating_sources", "evidence", "raw_sources")}
    row.update(scan_id=scan, cve_id="CVE-2024-1", package_name="OpenSSL", branch="3.0",
               spec_path="SPECS/openssl/openssl.spec", status="affected", description="Buffer overflow")
    db.replace_snapshot(pg, scan, [], [], [row], branches=["3.0"])
    items, total = db.list_findings(pg, search="openssl", branch="3.0")
    assert total == 1 and items[0]["package_name"] == "OpenSSL"


# -- SQLite -> PostgreSQL import --------------------------------------------------
def _sqlite_with_data(path):
    conn = db.connect(path)
    db.init_db(conn)
    scan = db.start_scan(conn, ["3.0"], "Azure Linux:3")
    conn.execute(
        "INSERT INTO findings (scan_id, cve_id, package_name, branch, spec_path, status) "
        "VALUES (?, 'CVE-2024-9', 'demo', '3.0', 'SPECS/demo/demo.spec', 'affected')", (scan,))
    db.upsert_triage(conn, "CVE-2024-9", "3.0", "SPECS/demo/demo.spec", package_name="demo", owner="x@y.z")
    db.add_finding_comment(conn, "CVE-2024-9", "3.0", "SPECS/demo/demo.spec", kind="comment", author="x", body="hi")
    conn.commit()
    conn.close()


@needs_pg
def test_import_copies_snapshot_and_triage_and_continues_ids(tmp_path, pg):
    src = tmp_path / "s.db"
    _sqlite_with_data(src)
    out = import_sqlite(src, pg, only="all")
    assert out["copied"]["findings"] == 1 and out["copied"]["finding_comments"] == 1
    assert db.get_triage(pg, "CVE-2024-9", "3.0", "SPECS/demo/demo.spec")["owner"] == "x@y.z"
    new = db.add_finding_comment(pg, "CVE-2024-9", "3.0", "SPECS/demo/demo.spec", kind="comment", author="y", body="next")
    assert new["id"] == 2  # the sequence moved past the imported row


@needs_pg
def test_import_never_overwrites_triage_without_force(tmp_path, pg):
    src = tmp_path / "s.db"
    _sqlite_with_data(src)
    import_sqlite(src, pg, only="all")
    db.add_finding_comment(pg, "CVE-2024-9", "3.0", "SPECS/demo/demo.spec", kind="comment", author="me", body="typed in the UI")
    again = import_sqlite(src, pg, only="all")
    assert "finding_comments" in again["skipped"]
    bodies = [c["body"] for c in db.finding_comments(pg, "CVE-2024-9", "3.0", "SPECS/demo/demo.spec")]
    assert "typed in the UI" in bodies
    forced = import_sqlite(src, pg, only="triage", force=True)
    assert forced["copied"]["finding_comments"] == 1


@needs_pg
def test_snapshot_only_import_leaves_triage_alone(tmp_path, pg):
    src = tmp_path / "s.db"
    _sqlite_with_data(src)
    db.add_finding_comment(pg, "CVE-2024-9", "3.0", "SPECS/demo/demo.spec", kind="comment", author="me", body="keep")
    out = import_sqlite(src, pg, only="snapshot")
    assert set(out["copied"]) == {"scans", "packages", "patches", "findings"}
    assert len(db.finding_comments(pg, "CVE-2024-9", "3.0", "SPECS/demo/demo.spec")) == 1


def test_import_rejects_bad_arguments(tmp_path):
    with pytest.raises(FileNotFoundError):
        import_sqlite(tmp_path / "missing.db", object())
    with pytest.raises(ValueError):
        import_sqlite(tmp_path / "x.db", object(), only="everything")


# -- unreachable database --------------------------------------------------------
SECRET = "s3cret-pw"
DEAD_URL = f"postgresql://postgres:{SECRET}@127.0.0.1:1/postgres"  # nothing listens on port 1


def test_hint_names_the_supabase_direct_host_problem():
    from vulnex.pgcompat import connection_hint

    hint = connection_hint("postgresql://postgres:pw@db.abcdefgh.supabase.co:5432/postgres")
    assert "Session pooler" in hint and "IPv6" in hint and "pw" not in hint
    assert "Session pooler" not in connection_hint("postgresql://u:pw@aws-0-x.pooler.supabase.com:5432/postgres")


@pytest.fixture()
def dead_db(monkeypatch):
    from vulnex import pgcompat

    monkeypatch.setattr(config, "DATABASE_URL", DEAD_URL)
    monkeypatch.setattr(pgcompat, "CONNECT_TIMEOUT", 1)
    yield
    pgcompat.close_pool()


def test_connect_raises_a_clean_error_without_the_password(dead_db):
    from vulnex.pgcompat import DatabaseUnavailable

    with pytest.raises(DatabaseUnavailable) as err:
        db.connect()
    assert SECRET not in str(err.value)


# -- first start on an empty Postgres ----------------------------------------------
@needs_pg
def test_empty_database_is_seeded_once_from_the_snapshot(tmp_path, pg):
    from vulnex.sqlite_import import seed_if_empty

    src = tmp_path / "s.db"
    _sqlite_with_data(src)
    first = seed_if_empty(pg, src)
    assert first["seeded"] is True and first["copied"]["findings"] == 1
    # A later start, or a newer snapshot in the repo, must not touch existing data.
    db.add_finding_comment(pg, "CVE-2024-9", "3.0", "SPECS/demo/demo.spec", kind="comment", author="me", body="mine")
    again = seed_if_empty(pg, src)
    assert again["seeded"] is False
    assert len(db.finding_comments(pg, "CVE-2024-9", "3.0", "SPECS/demo/demo.spec")) == 2


@needs_pg
def test_seed_without_a_snapshot_file_is_a_no_op(tmp_path, pg):
    from vulnex.sqlite_import import seed_if_empty

    out = seed_if_empty(pg, tmp_path / "missing.db")
    assert out["seeded"] is False and "no snapshot" in out["reason"]


@needs_pg
def test_backfill_fills_only_empty_first_seen_dates(tmp_path, pg):
    from vulnex.sqlite_import import backfill_first_seen

    src = tmp_path / "s.db"
    _sqlite_with_data(src)
    conn = db.connect(src)
    conn.execute("UPDATE findings SET first_seen = '2026-09-26T10:00:00Z'")
    conn.commit()
    conn.close()
    import_sqlite(src, pg, only="all")
    pg.execute("UPDATE findings SET first_seen = NULL")
    pg.commit()
    assert backfill_first_seen(pg, src) == 1
    assert pg.execute("SELECT first_seen FROM findings").fetchone()["first_seen"] == "2026-09-26T10:00:00Z"
    pg.execute("UPDATE findings SET first_seen = '2026-10-01T00:00:00Z'")
    pg.commit()
    backfill_first_seen(pg, src)  # nothing empty, so nothing changes
    assert pg.execute("SELECT first_seen FROM findings").fetchone()["first_seen"] == "2026-10-01T00:00:00Z"
