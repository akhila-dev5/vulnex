#!/bin/sh
# Apply the Alembic schema (idempotent; never blocks startup if the database is down),
# then start the .NET API on $PORT.
set -u
if [ -n "${DATABASE_URL:-}" ]; then
  (cd /app/backend && "$VULNEX_PYTHON" -m vulnex.engine_bridge migrate) \
    || echo "WARNING: database migration did not run; /api/health will report the database state."
fi
export PORT="${PORT:-10000}"
exec dotnet /app/api/Vulnex.Api.dll
