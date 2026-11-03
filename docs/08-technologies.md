# 8. Technologies

## Backend

| Technology | Used for | Why this one |
|------------|----------|--------------|
| **Python 3.11** | The whole backend and scanner | Good for text parsing and HTTP work |
| **FastAPI** | HTTP API | Typed, fast to write, automatic request validation |
| **Uvicorn** | Web server | Standard server for FastAPI |
| **Pydantic** | Request bodies | Validation with clear errors |
| **requests** | Calls to OSV, NVD, GitHub and others | Simple and reliable |
| **SQLite** | Scan snapshot, local dev, tests | Zero setup, one file |
| **PostgreSQL (Supabase)** | Live data | Survives redeploys; free tier |
| **psycopg 3 + psycopg-pool** | PostgreSQL driver and connection pool | Modern driver; pooling avoids a TLS handshake per request |
| **Alembic** | PostgreSQL schema migrations | Versioned, repeatable schema changes |
| **pytest** | Tests | Plain functions, good fixtures |

## Frontend

| Technology | Used for | Why this one |
|------------|----------|--------------|
| **React 18** | UI | Component model suits tables, modals and filters |
| **TypeScript** | Types across the app | Catches renamed fields from the API |
| **Vite 6** | Dev server and build | Fast, minimal config |
| **lucide-react** | Icons | Small, consistent icon set |
| **Vitest + Testing Library + jsdom** | Component and unit tests | Works directly with Vite |
| **Hash routing** (own `route.ts`) | Three pages | No router library, no server rewrite rules |

## Data and services

| Service | Role |
|---------|------|
| **OSV.dev** | Azure Linux advisories with version ranges |
| **NVD, MITRE, Red Hat, GitHub Advisories** | Severity, descriptions, upstream fixes |
| **GitHub REST API** | Reading specs, creating pull requests |
| **Google OAuth** | Admin sign-in |

## Hosting and automation

| Service | Role |
|---------|------|
| **Netlify** | Frontend hosting and `/api` proxy |
| **Render** | Backend hosting (free web service) |
| **Supabase** | Managed PostgreSQL |
| **GitHub Actions** | CI and the daily scan |
| **GitHub Pages** | Static read-only copy |

## Techniques worth knowing for questions about the project

- **RPM version comparison** (`rpmvercmp`) and why plain string or semver comparison fails
- **Backporting**: why an old version can still be safe
- **N+1 queries**: one query per row over a network database is slow; fixed by reading triage in one query
- **Connection pooling**: reuse connections instead of opening one per request
- **Caching with invalidation**: 60-second cache cleared on writes and after scans
- **Response compression**: GZip cut the list payload from about 291 KB to about 15 KB
- **Filtering and paging in SQL**: never load every row to filter in Python
- **OAuth 2.0 authorization code flow**: the Google sign-in
- **Role-based access**: viewer, admin, automation
- **Idempotent migrations and seeding**: safe to run again
- **Free-tier trade-offs**: cold starts, IPv6-only database hosts, ephemeral disks
