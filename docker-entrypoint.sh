#!/bin/sh
# Apply the Alembic schema, then start the .NET API on $PORT.
#   - database unreachable (exit 2): retry a few times, then start anyway so the API can
#     recover on its own; /api/health reports 503 until the schema is verified.
#   - migration failed (exit 1): do NOT start. A reachable database with a failed
#     migration is a deploy problem, and Render must keep the previous version running.
set -u
if [ -n "${DATABASE_URL:-}" ]; then
  attempt=1
  while : ; do
    (cd /app/backend && "$VULNEX_PYTHON" -m vulnex.engine_bridge migrate)
    rc=$?
    [ "$rc" -eq 0 ] && break
    if [ "$rc" -eq 2 ] && [ "$attempt" -lt 5 ]; then
      echo "Database unreachable (attempt $attempt/5); retrying in 5s."
      attempt=$((attempt + 1)); sleep 5; continue
    fi
    if [ "$rc" -eq 2 ]; then
      echo "WARNING: database still unreachable; starting anyway. /api/health will report 503."
      break
    fi
    echo "ERROR: database migration failed (exit $rc); refusing to start." >&2
    exit 1
  done
fi
export PORT="${PORT:-10000}"
exec dotnet /app/api/Vulnex.Api.dll
