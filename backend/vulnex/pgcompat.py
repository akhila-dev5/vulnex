"""PostgreSQL adapter that speaks the small sqlite3 surface ``db.py`` uses.

``db.py`` was written against :mod:`sqlite3` (``conn.execute(sql, params)``,
``?`` / ``:name`` placeholders, rows readable by column name, ``lastrowid``).
Rather than fork every query, :class:`PgConnection` translates the handful of
dialect differences on the way in, so both databases run the *same* SQL:

* ``?`` and ``:name`` placeholders  ->  ``%s`` / ``%(name)s``
* ``LIKE`` (case-insensitive in SQLite)  ->  ``ILIKE``
* ``cursor.lastrowid``  ->  ``INSERT ... RETURNING id``

Connections come from a small pool so each API request does not pay for a TLS
handshake to Supabase. The pool hands connections back on :meth:`close`.
"""

from __future__ import annotations

import atexit
import re
import threading
from typing import Any, Iterable
from urllib.parse import parse_qs, urlparse

import psycopg
from psycopg.rows import RowFactory
from psycopg_pool import ConnectionPool

__all__ = ["PgConnection", "connect", "normalize_url", "translate", "close_pool", "Row"]

# Tables whose primary key is not an ``id`` column (nothing to RETURN).
_NO_ID_TABLES = {"cve_cache"}

_INSERT_RE = re.compile(r"^\s*INSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
_LIKE_RE = re.compile(r"\bLIKE\b", re.IGNORECASE)
_NAMED_RE = re.compile(r"(?<![:\w]):([A-Za-z_][A-Za-z0-9_]*)")


class Row(dict):
    """A result row: ``row["col"]``, ``row[0]`` and ``dict(row)`` all work."""

    def __init__(self, columns: list[str], values: Iterable[Any]):
        values = list(values)
        super().__init__(zip(columns, values))
        self._values = values

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


def _row_factory(cursor) -> RowFactory:
    columns = [col.name for col in (cursor.description or [])]
    return lambda values: Row(columns, values)


def _protect_percent(sql: str) -> str:
    """A literal ``%`` in SQL (e.g. ``LIKE 'a%'``) must be doubled for psycopg."""
    return sql.replace("%", "%%")


def translate(sql: str, named: bool = False) -> str:
    """Rewrite one SQLite-flavoured statement for PostgreSQL."""
    out = _protect_percent(sql)
    out = _LIKE_RE.sub("ILIKE", out)
    if named:
        out = _NAMED_RE.sub(lambda m: f"%({m.group(1)})s", out)
    else:
        out = out.replace("?", "%s")
    return out


def normalize_url(url: str) -> str:
    """Accept ``postgres://`` and add ``sslmode=require`` for remote hosts."""
    url = url.strip()
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    parsed = urlparse(url)
    local = (parsed.hostname or "") in ("localhost", "127.0.0.1", "::1", "")
    if not local and "sslmode" not in parse_qs(parsed.query):
        url += ("&" if parsed.query else "?") + "sslmode=require"
    return url


class _Cursor:
    def __init__(self, cur: psycopg.Cursor, lastrowid: int | None = None):
        self._cur = cur
        self.lastrowid = lastrowid
        self.rowcount = cur.rowcount

    def fetchone(self):
        return self._cur.fetchone() if self._cur.description else None

    def fetchall(self):
        return self._cur.fetchall() if self._cur.description else []

    def __iter__(self):
        return iter(self.fetchall())


class PgConnection:
    """sqlite3-shaped wrapper around a pooled psycopg connection."""

    dialect = "postgres"

    def __init__(self, pool: ConnectionPool):
        self._pool = pool
        self._conn = pool.getconn()
        self._conn.row_factory = _row_factory
        self._closed = False

    # -- sqlite3-compatible surface ------------------------------------------
    def execute(self, sql: str, params: Iterable[Any] | dict | None = None) -> _Cursor:
        named = isinstance(params, dict)
        statement = translate(sql, named=named)
        insert = _INSERT_RE.match(sql)
        wants_id = (
            insert is not None
            and insert.group(1).lower() not in _NO_ID_TABLES
            and "RETURNING" not in statement.upper()
        )
        if wants_id:
            statement = statement.rstrip().rstrip(";") + " RETURNING id"
        cur = self._conn.cursor()
        cur.execute(statement, params if named else tuple(params or ()))
        lastrowid = None
        if wants_id and cur.description:
            first = cur.fetchone()
            lastrowid = int(first["id"]) if first else None
        return _Cursor(cur, lastrowid)

    def executemany(self, sql: str, seq: Iterable[Any]) -> None:
        rows = list(seq)
        if not rows:
            return
        named = isinstance(rows[0], dict)
        cur = self._conn.cursor()
        cur.executemany(translate(sql, named=named), rows)

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._conn.rollback()  # never hand back a connection mid-transaction
        finally:
            self._pool.putconn(self._conn)


_pools: dict[str, ConnectionPool] = {}
_lock = threading.Lock()


def _pool_for(url: str) -> ConnectionPool:
    with _lock:
        pool = _pools.get(url)
        if pool is None:
            pool = ConnectionPool(
                normalize_url(url),
                min_size=1,
                max_size=5,
                open=True,
                # Supabase's transaction pooler (port 6543) cannot use server-side
                # prepared statements, which psycopg enables after 5 executions.
                kwargs={"prepare_threshold": None, "autocommit": False},
                timeout=30,
            )
            _pools[url] = pool
        return pool


def connect(url: str) -> PgConnection:
    return PgConnection(_pool_for(url))


def close_pool(url: str | None = None) -> None:
    """Close one pool (or all). Tests and shutdown use this."""
    with _lock:
        for key in [url] if url else list(_pools):
            pool = _pools.pop(key, None)
            if pool is not None:
                pool.close()


atexit.register(close_pool)
