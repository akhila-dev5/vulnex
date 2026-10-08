"""Runtime configuration for VULNEX.

Everything is overridable through environment variables so the same code runs
locally, in CI, and inside GitHub Actions without code changes.
"""

from __future__ import annotations

import hmac
import os
import shutil
import subprocess
from pathlib import Path

# Project layout -----------------------------------------------------------
# config.py -> vulnex/ -> backend/ -> project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIR = PROJECT_ROOT / "frontend"
DATA_DIR = PROJECT_ROOT / "data"
CACHE_DIR = Path(os.environ.get("VULNEX_CACHE", DATA_DIR / "cache"))
DB_PATH = Path(os.environ.get("VULNEX_DB", DATA_DIR / "vulnex.db"))

# Azure Linux source repository -------------------------------------------
REPO_OWNER = os.environ.get("VULNEX_REPO_OWNER", "akhila-dev5")
REPO_NAME = os.environ.get("VULNEX_REPO_NAME", "azurelinux-test")
DEFAULT_BRANCHES = [
    b.strip()
    for b in os.environ.get("VULNEX_BRANCHES", "3.0-dev,fasttrack/3.0").split(",")
    if b.strip()
]

# Vulnerability intelligence ----------------------------------------------
# OSV publishes the official Microsoft Azure Linux advisory database under the
# "Azure Linux:<major>" ecosystem, with RPM version-release "fixed" events.
OSV_ECOSYSTEM = os.environ.get("VULNEX_OSV_ECOSYSTEM", "Azure Linux:3")
# Optional corroborating OSV ecosystems queried by package name (no version,
# used only to corroborate CVE identifiers, never as a direct range match).
CORROBORATION_ECOSYSTEMS = [
    e.strip()
    for e in os.environ.get(
        "VULNEX_CORROBORATION_ECOSYSTEMS", "Red Hat,Debian,Ubuntu,Alpine"
    ).split(",")
    if e.strip()
]

# The AI patch-remediation workflow will only ever target this repository.
PATCH_TARGET_REPO = os.environ.get("VULNEX_PATCH_TARGET_REPO", "akhila-dev5/azurelinux-test")

# This project's own repository (links in the README, not shown in the tool UI).
PROJECT_REPO = os.environ.get("VULNEX_PROJECT_REPO", "akhila-dev5/vulnex")
PROJECT_REPO_URL = os.environ.get(
    "VULNEX_PROJECT_REPO_URL", f"https://github.com/{PROJECT_REPO}"
)

# Site scope ----------------------------------------------------------------
# The console is about open exposures. A finding the distro has already fixed
# (``patched``), explicitly ruled out (a ``.nopatch`` marker → ``false_positive``)
# or could not classify (``unconfirmed``) is scanner output, not something this
# site shows. Every list, CVE page and export is restricted to this status, so
# an already-fixed CVE never appears in the UI.
OPEN_STATUS = "affected"

# Access tiers ---------------------------------------------------------------
# One team tool, three tiers. The tool is read-only by default.
#
#   viewer      anyone with the link: reads everything, writes nothing
#   admin       the human lead. Signs in with **email + password**, or with
#               **GitHub** (any account whose login is on the allow-list), and
#               receives an opaque session token. Full triage: patch verdicts,
#               disputes, comments, GitHub PR reference, queueing and scans.
#   automation  a narrowly-scoped machine identity that presents one static key
#               and may only set the GitHub CVE pull request (nothing else).
#
# There is no shared "access key" for people any more: a human credential is a
# session minted by /api/auth/login, never a long-lived string handed around.
ROLE_VIEWER = "viewer"
ROLE_ADMIN = "admin"
ROLE_AUTOMATION = "automation"

# Admin identity shown in the UI and stored on triage records.
ADMIN_IDENTITY = os.environ.get("VULNEX_ADMIN_IDENTITY", "akhila-dev5")
ADMIN_EMAIL = os.environ.get("VULNEX_ADMIN_EMAIL", "").strip().lower()

# The admin password. Set the PBKDF2 hash (preferred — generate it with
# ``python -m vulnex.cli hash-password``); the plaintext form is only a
# convenience for local development. Neither value is ever served by the API.
ADMIN_PASSWORD_HASH = os.environ.get("VULNEX_ADMIN_PASSWORD_HASH", "").strip()
ADMIN_PASSWORD = os.environ.get("VULNEX_ADMIN_PASSWORD", "")

# GitHub authentication for the admin. Create a GitHub OAuth App with the
# callback ``<deployment>/api/auth/github/callback`` and set the two credentials;
# a login is accepted only when it matches this allow-list.
ADMIN_GITHUB = os.environ.get("VULNEX_ADMIN_GITHUB", "akhila-dev5").strip().lower()
GITHUB_OAUTH_CLIENT_ID = os.environ.get("GITHUB_OAUTH_CLIENT_ID", "").strip()
GITHUB_OAUTH_CLIENT_SECRET = os.environ.get("GITHUB_OAUTH_CLIENT_SECRET", "").strip()
# Explicit redirect URI for deployments behind a proxy, where the request URL is
# not the public one. Defaults to the callback route on this host.
GITHUB_OAUTH_REDIRECT = os.environ.get("VULNEX_GITHUB_REDIRECT", "").strip()

# The automation machine identity keeps a static key (it is a machine, not a
# person, and rotates per deployment).
AUTOMATION_IDENTITY = os.environ.get("VULNEX_AUTOMATION_IDENTITY", "vulnex-sec")
AUTOMATION_EMAIL = os.environ.get(
    "VULNEX_AUTOMATION_EMAIL", "vulnexsecurityautomation@gmail.com"
)
AUTOMATION_KEY = os.environ.get("VULNEX_AUTOMATION_KEY") or "vulnex-sec"

# How long a sign-in stays valid (seconds).
SESSION_TTL = int(os.environ.get("VULNEX_SESSION_TTL", str(12 * 3600)))


def password_login_configured() -> bool:
    """True when the email + password login can actually be offered."""
    return bool(ADMIN_EMAIL and (ADMIN_PASSWORD_HASH or ADMIN_PASSWORD))


def github_login_configured() -> bool:
    """True when a GitHub OAuth app is configured for admin sign-in."""
    return bool(GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_CLIENT_SECRET)


def role_for_key(presented_key: str | None) -> str:
    """Map a machine key to a role, or ``viewer`` when it matches nothing.

    Compared with ``hmac.compare_digest`` so a wrong key cannot be found by
    timing. Only the automation identity authenticates this way.
    """
    if not presented_key:
        return ROLE_VIEWER
    if AUTOMATION_KEY and hmac.compare_digest(presented_key, AUTOMATION_KEY):
        return ROLE_AUTOMATION
    return ROLE_VIEWER


def identity_for(role: str) -> dict:
    """Identity metadata for a resolved role (never includes the key)."""
    if role == ROLE_ADMIN:
        return {"identity": ADMIN_IDENTITY, "email": ADMIN_EMAIL, "kind": "admin"}
    if role == ROLE_AUTOMATION:
        return {
            "identity": AUTOMATION_IDENTITY,
            "email": AUTOMATION_EMAIL,
            "kind": "automation",
        }
    return {"identity": "anonymous", "email": "", "kind": "viewer"}

# Endpoints ----------------------------------------------------------------
GITHUB_API = "https://api.github.com"
GITHUB_RAW = "https://raw.githubusercontent.com"
OSV_API = "https://api.osv.dev/v1"
REDHAT_SECURITY_API = "https://access.redhat.com/hydra/rest/securitydata"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_CVE_API = "https://cveawg.mitre.org/api/cve"
# Azure Linux binary/source blob store used to host release tarballs.
BLOB_STORE_BASE = "https://azurelinuxsrcstorage.blob.core.windows.net/sources/core"

# HTTP / scan tuning -------------------------------------------------------
HTTP_TIMEOUT = int(os.environ.get("VULNEX_HTTP_TIMEOUT", "30"))
SCAN_CONCURRENCY = int(os.environ.get("VULNEX_SCAN_CONCURRENCY", "16"))
ENRICH_CONCURRENCY = int(os.environ.get("VULNEX_ENRICH_CONCURRENCY", "12"))
# A scan with no explicit package filter is capped by this unless overridden.
DEFAULT_PACKAGE_LIMIT = int(os.environ.get("VULNEX_PACKAGE_LIMIT", "0"))  # 0 = all

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
NVD_API_KEY = os.environ.get("NVD_API_KEY")

_USER_AGENT = "vulnex/1.0 (+https://github.com/akhila-dev5/vulnex)"


def _gh_cli_token() -> str | None:
    """Best-effort token discovery from the GitHub CLI for local runs."""
    if not shutil.which("gh"):
        return None
    try:
        out = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, timeout=10
        )
        token = out.stdout.strip()
        return token or None
    except Exception:
        return None


def github_token() -> str | None:
    """Return a GitHub token if one is available, else ``None``.

    GitHub Actions injects ``GITHUB_TOKEN`` automatically. Locally we also fall
    back to an authenticated ``gh`` CLI so rate limits stay comfortable. The
    collector degrades gracefully (unauthenticated, 60 req/hr) without one.
    """
    return GITHUB_TOKEN or _gh_cli_token()


def user_agent() -> str:
    return _USER_AGENT


def repository_metadata() -> dict:
    """Scan-target metadata shared by the API and the static export.

    Deliberately tool-shaped: the dashboard is a security scanner, not a
    portfolio page, so no author/bio/architecture fields leak into the UI.
    """
    return {
        "owner": REPO_OWNER,
        "repo": REPO_NAME,
        "branches": list(DEFAULT_BRANCHES),
        "ecosystem": OSV_ECOSYSTEM,
        "patch_target_repo": PATCH_TARGET_REPO,
    }


def roles_metadata() -> dict:
    """The two authenticated identities, by name only — never the keys."""
    return {
        "admin": {
            "identity": ADMIN_IDENTITY,
            "email": ADMIN_EMAIL,
            "capabilities": ["triage", "dispute", "comment", "scan", "assign", "patch_verdict", "set_pr"],
        },
        "automation": {
            "identity": AUTOMATION_IDENTITY,
            "email": AUTOMATION_EMAIL,
            "capabilities": ["set_pr"],
        },
    }
