# 5. Database

Vulnex uses **SQLite** by default and **PostgreSQL** (Supabase) when the `DATABASE_URL` environment variable is set. The same query code runs on both.

## Which one is used when

| Situation | Database | Why |
|-----------|----------|-----|
| Local development, tests, the scanner | SQLite file `data/vulnex.db` | No server to install |
| Live site on Render | PostgreSQL on Supabase | Render's disk is wiped on every deploy, so a file would lose comments |

Without Supabase, everything people typed would disappear each time Render redeploys or restarts.

## Tables

Scan tables (replaced on every scan):

| Table | Holds |
|-------|-------|
| `scans` | One row per scan: time, branches, counts, duration, status |
| `packages` | One row per spec: name, version, release, EVR, spec path, source tarball, patch count |
| `patches` | Each `Patch:` entry in a spec: file name, CVE ids, whether it is a `.nopatch` marker, whether the file exists |
| `findings` | One row per CVE per package: status, severity, CVSS, confidence, evidence, advisory, `fixed_version` (upstream), `fixed_in`, `fixed_in_basis`, `fix_source`, `first_seen` (date first detected; carried forward across scans, so the CVE list can show the newest affected CVEs first) |

Triage tables (typed by people, never overwritten by a scan):

| Table | Holds |
|-------|-------|
| `finding_triage` | Per finding: triage status, resolution status, owner, final verdict, patch link, GitHub PR number and link |
| `finding_comments` | Comments on a finding |
| `disputes` | Dispute requests: package copied in, reason, status (`pending` / `approved` / `rejected`), who requested and who decided, decision note |
| `assignments` | Findings handed to patch automation, with status and assignee |
| `assignment_comments` | Comments on an assignment |
| `cve_cache` | Cached enrichment for a CVE so it is fetched once |

A finding is identified by **CVE id + branch + spec path**. `golang` has several specs (`golang.spec`, `golang-1.23.spec`, ...), so the spec path is part of the key.

## Indexes

`findings` is indexed on `status`, `severity`, `package_name`, `cve_id` and `spec_path`; `patches` and `packages` on package name; `finding_triage` on its key. These keep filtered list queries fast.

## Migrations

- **PostgreSQL** uses **Alembic**. Migrations are in `backend/migrations/versions/`, and `init_db` runs `alembic upgrade head` once per process.
- **SQLite** uses `CREATE TABLE IF NOT EXISTS` plus small in-place `ALTER TABLE ... ADD COLUMN` steps in `db.init_db` for older files.

When you change a table, add an Alembic revision for PostgreSQL **and** the matching SQLite step.

## How data gets in

1. The scanner writes a new snapshot into SQLite.
2. `vulnex migrate-sqlite --only snapshot` copies `scans`, `packages`, `patches` and `findings` into PostgreSQL. It is run by the scan workflow when the `DATABASE_URL` secret exists.
3. `--only all` copies everything once, used when first moving to Supabase.
4. On startup, an **empty** PostgreSQL database is seeded from `data/vulnex.db` so a fresh deployment is not blank.

On every start, PostgreSQL rows with an empty `first_seen` get their date from the bundled snapshot (`backfill_first_seen`), so the Scanned column fills in after a deploy without waiting for the next scan.

A non-empty triage table is never overwritten unless `--force` is passed.

## Connections

`pgcompat.py` keeps a small pool (1 to 5 connections) so a request does not pay for a new TLS handshake. It wraps psycopg 3 so the code can keep using `?` placeholders and row access by column name.

Supabase notes:

- The **direct** host is IPv6-only on the free plan and cannot be reached from Render or GitHub Actions. Use the **Session pooler** connection string (host like `aws-0-<region>.pooler.supabase.com`).
- A `@` inside the password is written `%40` in the URL.
- Keep Supabase in the same region as Render to avoid slow round trips.
