# Vulnex project notes

Short notes that explain how Vulnex works, one topic per file. Read them in order, or jump to the one you need.

| # | Note | Read it to understand |
|---|------|-----------------------|
| 1 | [Overview](01-overview.md) | What Vulnex is, who uses it, and the words used everywhere (CVE, spec, EVR, patched, fixed) |
| 2 | [Architecture](02-architecture.md) | The big picture: parts, how data flows, what happens on one page load |
| 3 | [Frontend](03-frontend.md) | The React app: pages, folders, how it talks to the API |
| 4 | [Backend](04-backend.md) | The FastAPI service: modules, API endpoints, sign-in and roles, caching |
| 5 | [Database](05-database.md) | Tables, SQLite vs PostgreSQL (Supabase), migrations, how data gets in |
| 6 | [Scanning and verification](06-scanning.md) | How CVEs are found, how "patched" is decided, the fixed-CVE list |
| 7 | [Deployment](07-deployment.md) | Render, Netlify, Supabase, GitHub Actions, and every setting |
| 8 | [Technologies](08-technologies.md) | Every tool used and why it was chosen |
| 9 | [Running it locally](09-running-locally.md) | Install, run, test, retake the screenshots |
| 10 | [Automation](10-automation.md) | How Automate patches CVEs and raises a draft PR in azurelinux-test, and the safety rules |

Screenshots used in these notes live in [`images/`](images/). Run `make screenshots` to retake them.
