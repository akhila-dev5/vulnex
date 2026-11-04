# 7. Deployment

Everything runs on free tiers.

| Service | Hosts | Config file |
|---------|-------|-------------|
| **Netlify** | The React app | `netlify.toml` |
| **Render** | The FastAPI service | `render.yaml` |
| **Supabase** | PostgreSQL | none (connection string only) |
| **GitHub Actions** | CI and the daily scan | `.github/workflows/ci.yml`, `scan.yml` |
| **GitHub Pages** | Read-only static copy | built by `scan.yml` |

## Netlify (frontend)

`netlify.toml` builds with `cd frontend && npm ci && npm run build`, publishes `frontend/dist`, uses Node 22, and **forwards `/api/*` to the Render URL**. The browser therefore talks to one origin: no CORS, and the Google sign-in redirect lands back on the Netlify site.

If the Render URL changes, edit the `to = ...` line in `netlify.toml`.

## Render (backend)

`render.yaml` is a Blueprint: Python service, free plan, region Oregon.

- Build: builds the frontend, then `pip install -r backend/requirements.txt`
- Start: `cd backend && uvicorn vulnex.api:app --host 0.0.0.0 --port $PORT`
- Health check: `/api/health`
- `PYTHON_VERSION` is pinned to `3.11.9`. If the service was created by hand instead of from the Blueprint, set this variable yourself.

The free plan **sleeps after about 15 minutes without traffic**; the next request waits 30 to 60 seconds. A free uptime monitor calling `/api/health` every 10 minutes avoids that.

## Environment variables (Render)

| Variable | Needed | Meaning |
|----------|--------|---------|
| `DATABASE_URL` | yes for persistence | Supabase **Session pooler** connection string |
| `VULNEX_ADMIN_EMAIL` | yes | Google account(s) allowed to sign in as admin |
| `GOOGLE_OAUTH_CLIENT_ID` | yes | From the Google Cloud OAuth client |
| `GOOGLE_OAUTH_CLIENT_SECRET` | yes | Same |
| `VULNEX_GOOGLE_REDIRECT` | optional | Override the OAuth callback URL when behind a proxy |
| `VULNEX_AUTOMATION_KEY` | optional | Static key for the automation role |
| `VULNEX_ALLOWED_ORIGINS` | optional | Extra CORS origins |
| `VULNEX_BRANCHES` | optional | Branches to scan, default `3.0,4.0` |
| `NVD_API_KEY` | optional | Higher NVD rate limit |

The Google OAuth client needs the redirect URI exactly `https://<your-site>/api/auth/google/callback`.

## Supabase (database)

1. Create a project.
2. Open **Connect** and copy the **Session pooler** string (not the direct one).
3. Replace `[YOUR-PASSWORD]` with your password; write `@` as `%40`.
4. Paste it as `DATABASE_URL` in Render, and as a GitHub Actions secret named `DATABASE_URL` if you want scans to refresh Supabase.
5. Choose the Supabase region closest to Render's Oregon region.

On first start the app creates the tables (Alembic) and seeds them from `data/vulnex.db`.

## GitHub Actions

- **`ci.yml`**: on pull requests and pushes to `main`. Backend tests on SQLite and PostgreSQL 16, then the frontend type check, tests and build.
- **`scan.yml`**: daily at 06:17 UTC and on demand. Runs backend tests, scans, syncs to Postgres (if the secret exists), prints stats, builds the static export, commits the new snapshot with `[skip ci]` so it does not loop, and deploys GitHub Pages.

Secrets used (all optional): `DATABASE_URL`, `NVD_API_KEY`, and `VULNEX_VULNDATA_TOKEN` (a token with write access to `VulnerabilityData`, so the scan can publish the fixed-CVE list there as a pull request). `GITHUB_TOKEN` is provided automatically.

After the scan, findings that are 100% patched **and already recorded** in the `VulnerabilityData` fixed-CVE list are deleted to save space (see [Scanning](06-scanning.md)).

## Releasing a change

1. Open a pull request. CI must pass.
2. Merge to `main`. Render redeploys automatically (`autoDeployTrigger: checksPass`) and Netlify rebuilds.
3. The next scan refreshes the data.
