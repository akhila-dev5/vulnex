import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))


# -- optional: run the whole suite against PostgreSQL --------------------------
# ``VULNEX_TEST_DATABASE_URL=postgresql://... pytest`` points every test that
# opens the default database (``db.connect()`` with no path) at a real Postgres
# and starts each test from empty tables. Tests that pass an explicit SQLite path
# keep using SQLite. Without the variable nothing changes.
from vulnex import config, db  # noqa: E402

_PG_URL = os.environ.get("VULNEX_TEST_DATABASE_URL", "")


@pytest.fixture(autouse=True)
def _postgres_backend(monkeypatch):
    if not _PG_URL:
        yield
        return
    monkeypatch.setattr(config, "DATABASE_URL", _PG_URL)
    conn = db.connect()
    try:
        db.init_db(conn)
        tables = [
            r["table_name"]
            for r in conn.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_name <> 'alembic_version'"
            ).fetchall()
        ]
        conn.execute("TRUNCATE " + ", ".join(tables) + " RESTART IDENTITY")
        conn.commit()
    finally:
        conn.close()
    yield
