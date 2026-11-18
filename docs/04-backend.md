# 4. Backend

The web API is an **ASP.NET Core (.NET 10)** app in `api/Vulnex.Api/` (see [11 · .NET backend](11-dotnet-backend.md) for its files). One process serves the JSON API and the built React app. The Python in `backend/vulnex/` is the engine: scanner, enrichment, fixed-CVE ledger, migrations and the automation worker. The table below describes that Python engine.

## Module map

| File | Job |
|------|-----|
| `config.py` | Settings read from environment variables (repo, branches, OAuth, database URL) |
| `db.py` | Table definitions and the queries the scanner and CLI use (the API has its own SQL in `api/Vulnex.Api/Repo.cs`) |
| `pgcompat.py` | Lets the SQLite-style query code run on PostgreSQL (psycopg 3 and a connection pool) |
| `scanner.py` | Runs a scan from start to finish |
| `azurelinux.py` | Reads the `.spec` tree from GitHub |
| `spec_parser.py` | Reads name, version, release, `Patch:` lines, changelog from a spec |
| `rpmvercmp.py` | RPM version comparison (`1.0~rc1 < 1.0`) |
| `verification.py` | Decides affected / patched / false positive / unconfirmed, with evidence |
| `sources/` | One client per data source: `osv.py`, `nvd.py`, `mitre.py`, `redhat.py`, `ghsa.py`, `vulnerabilitydata.py` |
| `enrichment.py` | Adds severity, references and upstream fix links from several sources |
| `triage.py` | Derived views: tracker links, patch availability, Deep view, Azure Linux fixed version |
| `fixed_cves.py` | Builds and publishes the fixed-CVE list |
| `export.py` | Builds the static GitHub Pages copy |
| `sqlite_import.py` | Copies the SQLite snapshot into PostgreSQL |
| `engine_bridge.py` | JSON command line the .NET API calls for enrichment, the fixed-CVE ledger, the VulnerabilityData feed and scans |
| `cli.py` | The `vulnex` command (`scan`, `stats`, `export`, `fixed-cves`, `migrate-sqlite`, `vuln-data`) |

## API endpoints

Read endpoints are open to everyone. Write endpoints need the admin session (or, for the PR link only, the automation key).

| Method and path | Purpose |
|-----------------|---------|
| `GET /api/health` | Is the app up, and can it reach its database |
| `GET /api/role` | Caller's role and what they can do; which sign-in methods exist |
| `GET /api/auth/google`, `/api/auth/google/callback` | Start and finish Google sign-in |
| `POST /api/auth/logout` | End the session |
| `GET /api/stats` | Summary numbers for the cards (optionally per branch) |
| `GET /api/findings` | The CVE list with filters and paging |
| `GET /api/cves/{id}` | One CVE with all its findings, links and triage |
| `GET /api/cves/{id}/deep` | Deep view: affected files, backport patches, upstream fixed version |
| `GET /api/packages`, `/api/packages/{name}` | Package list and detail |
| `GET /api/fixed-cves` | The fixed-CVE list |
| `GET /api/vulnerability-data...` | NVD inventory from the VulnerabilityData repo |
| `GET /api/triage`, `/api/triage/comments` | Triage records and comments |
| `POST /api/triage/comment` · `dispute` · `patch` | Add a comment (dev or admin), raise a dispute (dev or admin; waits for approval), set a patch verdict (admin) |
| `POST /api/cves/{id}/rescore` | Admin only. Replaces a CVE's severity and CVSS score; needs a severity, an optional score (0 to 10) and a reason |
| `POST /api/triage/claim` · `release` | Developer or admin. Claim sets the package's owner to the caller (409 if another developer owns it; the admin may take over). Release clears it |
| `GET /api/workflows` | Developer or admin only (401 otherwise). Every developer's packages grouped by owner (assignee, else claimer): `groups[]` with the caller first, then alphabetical; each item has `held_via` = `assigned` or `claimed` |
| `GET /api/automation` | Developer or admin only. The automation account's open CVEs whose final patch verdict is Patch Available, grouped by package spec (`packages[]`, each with `items[]` and its latest `requests`) |
| `POST /api/automation/requests` | Developer or admin only. Queue the ticked CVEs of one package into a single PR: `mode` is `new_pr` or `existing_pr` (which needs a numeric `pr_number`). The server re-checks the CVEs are ready. It only records the request (status `queued`); the automation that raises the PR picks it up |
| `POST /api/automation/jobs/next` | Automation key only. Hands the worker the oldest queued request (marked running) with each CVE's severity, description and upstream patch link |
| `POST /api/automation/jobs/{id}/result` | Automation key only. The worker reports `done`, `partial` or `failed` with the PR link |
| `GET /api/disputes` | Dispute requests with counts per status (`status`, `search`, `page`) |
| `POST /api/disputes/{id}/approve` · `reject` | Admin decision. Approve marks the package Disputed; reject leaves it unchanged |
| `POST /api/triage/github-pr`, `google-pr` | Attach a pull request link |
| `GET/POST /api/assignments`, `.../comments` | Hand a finding to patch automation |
| `POST /api/scan`, `GET /api/scan/status`, `GET /api/scans` | Start a scan, check progress, scan history |

`GET /api/findings` accepts: `severity`, `status`, `search`, `package`, `branch`, `page`, `limit`, `patch_state`, `triage_status`, `resolution_status`, `owner`, `fixed_version`.

## Sign-in and roles

- **Admin** signs in with Google. Only the emails in `VULNEX_ADMIN_EMAIL` are accepted. The server creates a random session token, held in memory, and the browser sends it in the `X-VULNEX-Key` header.
- **Developer** also signs in with Google, but only emails in `VULNEX_DEVELOPER_EMAILS` or the built-in list in `config.py` (`vulnexsecurityautomation@gmail.com`). They can comment, set the PR link, raise disputes and claim packages.
- Only the admin can **rescore** a CVE (`rescore` capability, `can_rescore` in `/api/role`).
- **Automation** sends the static `VULNEX_AUTOMATION_KEY` and may only set the PR link.
- **Viewer** has no credential and gets read-only access.
- A dispute raised by a developer is `pending`. The admin approves it on the Disputes page, which adds the reason to the package history and sets its triage and resolution status to `disputed`. A dispute raised by the admin is approved at once.
- Each role maps to a set of allowed actions (`Roles.Capabilities` in `api/Vulnex.Api/Auth.cs`). `require_admin` returns HTTP 401 for anything else.

## How a list request is served

1. The `/api/findings` handler builds a cache key from every query parameter.
2. On a miss, `Repo.ListFindings` filters, joins triage data, sorts by severity and pages **in SQL**.
3. Only the rows on that page get derived fields (`patch_availability`, `azl_fixed_version`, triage, assignment).
4. ASP.NET Core sends the result through gzip response compression.
5. Any write request, and the end of a scan, clears the cache. A 60-second expiry covers changes made by another process, such as the scheduled scan.

List rows are deliberately light: tracker links and the Deep view load only when a CVE or Deep is opened.

## Fixed version fields

| Field | Meaning | Where it shows |
|-------|---------|----------------|
| `fixed_in` / `azl_fixed_version` | azurelinux-test version-release where the CVE was patched. Only set for patched findings | "Fixed version" column |
| `fixed_version` | Upstream project's fixed version, from the advisory | Deep view only |

## Testing

```bash
cd backend && pytest -q
```

Tests run on SQLite. Set `VULNEX_TEST_DATABASE_URL` to also run the PostgreSQL tests. `tests/conftest.py` clears the response cache between tests.
