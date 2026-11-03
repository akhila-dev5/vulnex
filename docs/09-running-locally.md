# 9. Running it locally

## You need

- Python 3.11 or newer
- Node 22 (only to build or work on the frontend)

## Backend

```bash
make install        # creates backend/.venv and installs dependencies
make test           # backend tests
make serve          # API on http://localhost:8000
```

Or by hand:

```bash
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements-dev.txt
cd backend
python -m pytest -q
python -m vulnex.cli serve --port 8000
```

With no `DATABASE_URL`, the app reads `data/vulnex.db` (the bundled snapshot). Set `DATABASE_URL` to a PostgreSQL URL to use Postgres instead.

## Frontend

```bash
cd frontend
npm ci
npm run build       # backend serves frontend/dist at http://localhost:8000
# or, for live reload while editing:
npm run dev         # needs the backend running for /api
```

## Run a scan

```bash
cd backend
python -m vulnex.cli scan --branches 3.0                       # full scan
python -m vulnex.cli scan --branches 3.0 --packages curl,zlib --no-enrich   # quick test
python -m vulnex.cli stats                                     # totals as JSON
```

A scan needs no credentials. A `GITHUB_TOKEN` only raises the GitHub rate limit.

## Command line reference

| Command | Does |
|---------|------|
| `scan` | Run a scan and replace the snapshot |
| `stats` | Print dashboard totals |
| `serve` | Run the API (and the built frontend) |
| `export` | Build the static GitHub Pages copy |
| `fixed-cves` | Build or publish the fixed-CVE list |
| `migrate-sqlite` | Copy the snapshot into PostgreSQL |
| `vuln-data` | Show the NVD inventory from VulnerabilityData |

Add `--help` to any command for its options.

## Retake the screenshots

```bash
make serve                      # in one terminal
pip install playwright && python -m playwright install chromium
make screenshots                # writes docs/images/*.png
```

## Tests

| What | Command |
|------|---------|
| Backend (SQLite) | `cd backend && pytest -q` |
| Backend (PostgreSQL too) | `VULNEX_TEST_DATABASE_URL=postgresql://... pytest -q` |
| Frontend | `cd frontend && npm test` |
| Types | `cd frontend && npm run typecheck` |
