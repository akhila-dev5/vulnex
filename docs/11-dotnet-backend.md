# 11 · .NET backend (migration)

The web API is now **ASP.NET Core (.NET 10)** in `api/`. The Python code stays for what it is
good at: the scanner, CVE enrichment, the fixed-CVE ledger, the VulnerabilityData reader and the
automation worker (`python -m vulnex.automation`).

```
browser ──► .NET API (api/Vulnex.Api) ──► PostgreSQL (schema owned by Alembic, unchanged)
                 │
                 └─ subprocess ─► python -m vulnex.engine_bridge  (enrich, fixed-cves, vuln-data, scan)
```

## What did not change

* Every URL, query parameter, status code and JSON field — the React app and the automation
  worker need no change.
* Every environment variable and secret name: `DATABASE_URL`, `GOOGLE_OAUTH_CLIENT_ID`,
  `GOOGLE_OAUTH_CLIENT_SECRET`, `VULNEX_DEVELOPER_EMAILS`, `VULNEX_AUTOMATION_KEY`,
  `VULNEX_AUTOMATION_EMAIL`, `VULNEX_AUTOMATION_IDENTITY`, `VULNEX_DISPATCH_TOKEN`,
  `VULNEX_DISPATCH_REPO`, `VULNEX_ALLOWED_ORIGINS`, … plus the GitHub Actions secrets
  (`AZL_TEST_TOKEN`, `VULNEX_API_URL`, `VULNEX_AUTOMATION_KEY`, …).
* The database schema (Alembic `0001`–`0006`). The container runs `alembic upgrade head`
  through `engine_bridge migrate` before the API starts.

## Layout

| File | Role |
|------|------|
| `Program.cs` | Host setup: CORS, gzip, JSON `{"detail": …}` errors, cache clearing on writes, React files |
| `Endpoints.cs` | All ~40 routes, ported one-to-one from the removed `backend/vulnex/api.py` |
| `Repo.cs`, `Sql.cs` | SQL ported from `db.py`; thin ADO.NET helper with named parameters |
| `Triage.cs` | Patch availability, Deep view, tracker links (from `triage.py`) |
| `Auth.cs`, `Config.cs` | Roles, in-memory sessions, Google OAuth, settings |
| `Engine.cs` | Runs the Python engine bridge; background scan manager |
| `PgFactory.cs` | The only file that uses Npgsql; converts `DATABASE_URL` |

## Testing

The old Python API (`api.py`, `auth.py`, `cache.py`) and its tests are **deleted** in this migration, so
what runs on `dev` is only the .NET API. Its behaviour is pinned by tests in `api/Vulnex.Api.Tests`:

* `GoldenTests`: every read endpoint must answer exactly the JSON recorded from the original Python API
  (`golden/*.json`, 40 endpoints, recorded by `scripts/api_snapshots.py record` before the deletion).
* `WorkflowTests` and `AutomationTests`: who may do what, claims, disputes, rescoring, the Automation
  section and the worker's job endpoints (ported from the Python tests).
* `CoreTests`: sessions, roles, tracker links, patch availability.

They need a PostgreSQL database seeded with `python scripts/api_snapshots.py seed` and `DATABASE_URL` set;
CI does this (see the `dotnet-api` job in `.github/workflows/ci.yml`).

## Trying it on `dev`

1. Create a second Render web service from this repo, branch `dev`, runtime Docker, with the
   same environment variables as production. `DATABASE_URL` is the **same Supabase database**,
   so anything you write while testing (comments, claims, PR links) is real data.
2. Add the new service's `/api/auth/google/callback` URL to the Google OAuth client.
3. Point a Netlify branch deploy (or a local `VITE_API` proxy) at the new service.
4. If everything works, merge `dev` into `main`; the existing Render service rebuilds from the Dockerfile.
