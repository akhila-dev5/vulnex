"""Runtime configuration for VULNEX.

Everything is overridable through environment variables so the same code runs
locally, in CI, and inside GitHub Actions without code changes.
"""

from __future__ import annotations

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
