# 9. Running it locally

## You need

- .NET 10 SDK (the API) and Python 3.11 or newer (the engine)
- PostgreSQL (the API needs `DATABASE_URL`; there is no SQLite mode any more)
- Node 22 (only to build or work on the frontend)

## Backend

```bash
make install        # creates backend/.venv and installs dependencies
make test           # backend tests
export DATABASE_URL=postgresql://...   # required
make serve          # .NET API on http://localhost:8000
```

Or by hand:

```bash
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements-dev.txt
cd backend && python -m pytest -q && cd ..
dotnet test api/Vulnex.sln          # needs DATABASE_URL seeded by scripts/api_snapshots.py
VULNEX_PYTHON=$PWD/backend/.venv/bin/python VULNEX_BACKEND_DIR=$PWD/backend PORT=8000 dotnet run --project api/Vulnex.Api
```

The scanner and CLI still work on the SQLite file `data/vulnex.db` when `DATABASE_URL` is unset. Load that snapshot into PostgreSQL with `python -m vulnex.cli migrate-sqlite --only snapshot`. The API itself only talks to PostgreSQL.

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
