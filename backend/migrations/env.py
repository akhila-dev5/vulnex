"""Alembic environment: the target database comes from DATABASE_URL (or -x url=)."""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import create_engine, pool

from vulnex.pgcompat import normalize_url

config = context.config


def _url() -> str:
    url = (
        config.attributes.get("url")
        or context.get_x_argument(as_dictionary=True).get("url")
        or os.environ.get("DATABASE_URL", "")
    )
    if not url:
        raise RuntimeError("Set DATABASE_URL (or pass -x url=...) to run migrations.")
    url = normalize_url(url)
    # SQLAlchemy needs the driver named explicitly; the app uses psycopg 3.
    return url.replace("postgresql://", "postgresql+psycopg://", 1)


def run_migrations_offline() -> None:
    context.configure(url=_url(), literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
