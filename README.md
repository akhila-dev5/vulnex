# Vulnex

**An Azure Linux CVE detection & remediation platform.**

Vulnex combines two cooperating projects into one workspace:

| Folder | Role |
| --- | --- |
| [`cve-scanner/`](./cve-scanner) | **Detection engine (data source).** Scans Azure Linux RPM specs, builds an SBOM, runs Grype, verifies findings (OSV/MITRE/NVD/Debian) and produces `verified.json`. |
| [`cve-platform/`](./cve-platform) | **Remediation platform.** FastAPI backend + static dashboard for users, CVE assignment, workload, AI recommendations and remediation tracking. |

The scanner is the source of truth for **vulnerability detection**; the platform
is the source of truth for **ownership and remediation workflow**.

```
Azure Linux SPECS ─► cve-scanner ─► verified.json ─► /api/cves/sync ─► cve-platform ─► Dashboard
                       (detect + verify)                 (assign, track, AI recommend)
```

## Run locally

**1. Backend (FastAPI, Python 3.10+)**

```bash
cd cve-platform
python3 -m pip install -r requirements.txt
python3 -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
# API docs: http://127.0.0.1:8000/docs
```

**2. Frontend (static)**

```bash
cd cve-platform/frontend
python3 -m http.server 8080 --bind 127.0.0.1
# open http://127.0.0.1:8080/index.html
```

The frontend auto-detects localhost and calls the backend on `:8000`
(see `cve-platform/frontend/assets/js/config.js`).

**3. Feed scanner data into the platform (optional)**

```bash
# after the scanner has produced verified.json
cd cve-platform
python3 scripts/sync_from_scanner.py --in ../cve-scanner/verified.json --api http://127.0.0.1:8000
```

## Deploy (all free tiers)

```
Frontend ─► Netlify        (deploys cve-platform/frontend, see netlify.toml)
Backend  ─► Render         (see render.yaml)
Database ─► Supabase Postgres (set DATABASE_URL on Render)
```

Before deploying, set:
- `PROD_API_BASE_URL` in `cve-platform/frontend/assets/js/config.js` → your Render URL.
- `CORS_ORIGINS` on Render → your Netlify site origin.

## Notes

- Personal reimplementation for learning; uses mock/demo data only.
- `cve-platform` runs on SQLite locally and Postgres/Supabase in production.
- The scanner keeps its own `.gitignore` for regenerated artifacts
  (`grype.json`, `sbom.json`, `inventory.*`, `site/`).
