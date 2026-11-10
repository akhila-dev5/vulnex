"""Raising the pull request, with hard guards so it can only ever go to azurelinux-test.

Every GitHub call in this module is built from ``ALLOWED_REPO``. No function accepts a
repository name, a URL or a base branch from outside, and every response is checked to be
for ALLOWED_REPO before it is trusted.
"""

from __future__ import annotations

import re

import requests

from .. import config

ALLOWED_REPO = "akhila-dev5/azurelinux-test"  # deliberately a constant, not a setting
FASTTRACK = "fasttrack/3.0"
DEV = "3.0-dev"
ALLOWED_BASES = (FASTTRACK, DEV)  # never the release branch 3.0
API = "https://api.github.com"
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class TargetRepoError(RuntimeError):
    """Raised whenever anything would point somewhere other than azurelinux-test."""


def assert_target_repo() -> None:
    """The configured patch target must be exactly the allowed repository."""
    if (config.PATCH_TARGET_REPO or "").strip().lower() != ALLOWED_REPO.lower():
        raise TargetRepoError(
            f"VULNEX_PATCH_TARGET_REPO is {config.PATCH_TARGET_REPO!r}; automation only works on {ALLOWED_REPO}."
        )


def assert_remote(url: str) -> None:
    """A git remote must be https://github.com/akhila-dev5/azurelinux-test (any credentials stripped)."""
    bare = re.sub(r"^https://[^@/]*@", "https://", url.strip()).removesuffix(".git").rstrip("/")
    if bare.lower() != f"https://github.com/{ALLOWED_REPO}".lower():
        raise TargetRepoError(f"Refusing to use remote {bare!r}")


def check_token_owner(token: str, expected_login: str = "", session=None) -> str:
    """Make sure the token belongs to the automation account, not to a person.

    GitHub credits PRs, descriptions and comments to whoever owns the token, so a token made
    from the repository owner's own account makes Vulnex's PRs look like that person wrote them.
    ``expected_login`` is the automation account's GitHub username
    (VULNEX_AUTOMATION_GITHUB_LOGIN). When it is not set, the repository owner's own login is
    refused. Returns the token owner's login.
    """
    http = session or requests
    response = http.get(f"{API}/user", headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}, timeout=30)
    if response.status_code != 200:
        raise TargetRepoError(f"GitHub did not accept AZL_TEST_TOKEN ({response.status_code}). Is it expired or revoked?")
    login = (response.json().get("login") or "").lower()
    owner = ALLOWED_REPO.split("/")[0].lower()
    expected = (expected_login or "").strip().lower()
    if expected and login != expected:
        raise TargetRepoError(f"AZL_TEST_TOKEN belongs to {login!r}, but VULNEX_AUTOMATION_GITHUB_LOGIN is {expected!r}. Create the token while signed in as the automation account.")
    if not expected and login == owner:
        raise TargetRepoError(
            f"AZL_TEST_TOKEN belongs to {login!r}, the owner of {ALLOWED_REPO}, so every PR would be credited to that person. "
            "Create the token while signed in as the automation account (see docs/10-automation.md), "
            "or set VULNEX_AUTOMATION_GITHUB_LOGIN to this login if that is intended."
        )
    return login


def assert_head_branch(name: str) -> None:
    """Automation only pushes to its own topic branches, never to a base branch."""
    if not name.startswith("topic/") or name in ALLOWED_BASES:
        raise TargetRepoError(f"Refusing to push to branch {name!r}")


def highest_severity(severities: list[str]) -> str:
    return max((s.lower() for s in severities), key=lambda s: SEVERITY_ORDER.get(s, 0), default="low")


def base_branch_for(severities: list[str]) -> str:
    """High or critical goes to fasttrack/3.0; medium and low to 3.0-dev; the highest one wins."""
    return FASTTRACK if SEVERITY_ORDER.get(highest_severity(severities), 0) >= 3 else DEV


def branch_name(package: str, cve_ids: list[str]) -> str:
    return f"topic/{package}/3.0/{sorted(cve_ids)[0]}"


def pr_title(package: str, cve_ids: list[str], severity: str) -> str:
    return f"[Vulnex-AutoPR] Patch {package} for {', '.join(cve_ids)} [{severity.upper()}]"


def _check_repo(payload: dict, *keys: str) -> None:
    for key in keys:
        full = (((payload.get(key) or {}).get("repo") or {}).get("full_name") or "").lower()
        if full != ALLOWED_REPO.lower():
            raise TargetRepoError(f"GitHub says the pull request {key} is in {full!r}, not {ALLOWED_REPO}")


class GitHub:
    """The only GitHub client the automation uses. ``session`` is injectable for tests."""

    def __init__(self, token: str, session=None):
        assert_target_repo()
        self.token = token
        self.session = session or requests.Session()

    def _call(self, method: str, path: str, **kwargs) -> dict:
        response = self.session.request(
            method, f"{API}/repos/{ALLOWED_REPO}{path}",
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json"},
            timeout=60, **kwargs,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"GitHub {method} {path} failed: {response.status_code} {response.text[:300]}")
        return response.json()

    def get_pull(self, number: int) -> dict:
        """An open pull request on a topic branch of ALLOWED_REPO, targeting an allowed base."""
        pr = self._call("GET", f"/pulls/{number}")
        _check_repo(pr, "base", "head")
        if pr.get("state") != "open":
            raise TargetRepoError(f"PR #{number} is not open")
        if pr["base"]["ref"] not in ALLOWED_BASES:
            raise TargetRepoError(f"PR #{number} targets {pr['base']['ref']!r}, not {ALLOWED_BASES}")
        assert_head_branch(pr["head"]["ref"])
        return pr

    def create_draft_pr(self, head: str, base: str, title: str, body: str) -> dict:
        assert_head_branch(head)
        if base not in ALLOWED_BASES:
            raise TargetRepoError(f"Refusing to open a PR against {base!r}")
        pr = self._call("POST", "/pulls", json={"title": title, "head": head, "base": base, "body": body, "draft": True})
        _check_repo(pr, "base", "head")
        return pr

    def comment(self, number: int, body: str) -> None:
        self._call("POST", f"/issues/{number}/comments", json={"body": body})
