"""Azure Linux source-repository collector.

Pulls the *real* ``SPECS/`` tree from the configured Azure Linux GitHub
repository (default: ``akhila-dev5/azurelinux-test``, branches ``3.0-dev`` and
``fasttrack/3.0``), fetches each ``.spec`` file and parses it. Nothing here is
hard-coded package data — refreshing the dashboard re-reads the live repository.

Design notes
------------
* The git *tree* API returns every blob path in a single request, so we can
  discover all specs without cloning the (multi-hundred-MB) repository.
* Spec files are fetched from ``raw.githubusercontent.com`` pinned to the
  branch commit SHA. Raw hosts are not API-rate-limited, so a full-distro scan
  stays well inside GitHub's limits.
* All network results are cached on disk under ``data/cache``.
"""

from __future__ import annotations

import json
import posixpath
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import quote

import requests

from . import config
from .spec_parser import ParsedSpec, parse_spec

__all__ = ["AzureLinuxRepo", "RepositoryError"]


class RepositoryError(RuntimeError):
    """Raised when the Azure Linux repository cannot be read."""


@dataclass
class TreeEntry:
    path: str
    sha: str
    type: str
    size: int = 0


class AzureLinuxRepo:
    """Read-only client for an Azure Linux source repository."""

    def __init__(
        self,
        owner: str | None = None,
        repo: str | None = None,
        token: str | None = None,
        cache_dir=None,
        session: requests.Session | None = None,
    ) -> None:
        self.owner = owner or config.REPO_OWNER
        self.repo = repo or config.REPO_NAME
        self.token = token if token is not None else config.github_token()
        self.cache_dir = cache_dir or (config.CACHE_DIR / "repo" / f"{self.owner}-{self.repo}")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = session or requests.Session()
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": config.user_agent(),
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self.session.headers.update(headers)

    # -- API helpers -------------------------------------------------------
    def _api(self, path: str) -> dict:
        url = f"{config.GITHUB_API}{path}"
        resp = self.session.get(url, timeout=config.HTTP_TIMEOUT)
        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            hint = (
                "GitHub API rate limit exceeded. Set GITHUB_TOKEN/GH_TOKEN "
                "or authenticate the gh CLI to raise the limit."
            )
            raise RepositoryError(hint)
        if resp.status_code >= 400:
            raise RepositoryError(
                f"GitHub API {path} failed: {resp.status_code} {resp.text[:200]}"
            )
        return resp.json()

    def branch_sha(self, branch: str) -> str:
        cache = self.cache_dir / f"branch_{quote(branch, safe='')}.sha"
        if cache.exists():
            return cache.read_text().strip()
        data = self._api(f"/repos/{self.owner}/{self.repo}/branches/{quote(branch, safe='')}")
        sha = data["commit"]["sha"]
        cache.write_text(sha)
        return sha

    def tree(self, branch: str) -> list[TreeEntry]:
        sha = self.branch_sha(branch)
        cache = self.cache_dir / f"tree_{sha}.json"
        if cache.exists():
            raw = json.loads(cache.read_text())
        else:
            data = self._api(
                f"/repos/{self.owner}/{self.repo}/git/trees/{quote(branch, safe='')}?recursive=1"
            )
            if data.get("truncated"):
                raise RepositoryError(
                    "Repository tree was truncated by GitHub; cannot enumerate all specs."
                )
            raw = data["tree"]
            cache.write_text(json.dumps(raw))
        return [
            TreeEntry(
                path=e["path"],
                sha=e.get("sha", ""),
                type=e.get("type", ""),
                size=e.get("size", 0) or 0,
            )
            for e in raw
        ]

    def spec_paths(self, branch: str, include_extended: bool = False) -> list[TreeEntry]:
        roots = ("SPECS/", "SPECS-EXTENDED/", "SPECS-SIGNED/") if include_extended else ("SPECS/",)
        return [
            e
            for e in self.tree(branch)
            if e.type == "blob" and e.path.endswith(".spec") and e.path.startswith(roots)
        ]

    def present_files(self, branch: str) -> set[str]:
        return {e.path for e in self.tree(branch)}

    def raw_url(self, branch: str, path: str) -> str:
        sha = self.branch_sha(branch)
        return f"{config.GITHUB_RAW}/{self.owner}/{self.repo}/{sha}/{path}"

    def fetch_raw(self, branch: str, path: str, use_cache: bool = True) -> str:
        sha = self.branch_sha(branch)
        cache = self.cache_dir / "files" / sha / path
        if use_cache and cache.exists():
            return cache.read_text(errors="replace")
        url = f"{config.GITHUB_RAW}/{self.owner}/{self.repo}/{sha}/{path}"
        resp = self.session.get(url, timeout=config.HTTP_TIMEOUT)
        if resp.status_code >= 400:
            raise RepositoryError(f"Failed to fetch {url}: HTTP {resp.status_code}")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(resp.text)
        return resp.text

    def fetch_patch(self, branch: str, patch_path: str) -> str | None:
        """Best-effort fetch of a patch file body (used for affected-file lists)."""
        try:
            return self.fetch_raw(branch, patch_path)
        except RepositoryError:
            return None

    def collect(
        self,
        branch: str,
        packages: set[str] | None = None,
        limit: int = 0,
        include_extended: bool = False,
        progress=None,
    ) -> list[ParsedSpec]:
        """Fetch and parse every spec (or a filtered subset) for ``branch``."""
        entries = self.spec_paths(branch, include_extended=include_extended)
        present = self.present_files(branch)
        if packages:
            wanted = {p.lower() for p in packages}
            entries = [e for e in entries if e.path.split("/")[1].lower() in wanted]
        if limit and limit > 0:
            entries = entries[:limit]

        specs: list[ParsedSpec] = []

        def work(entry: TreeEntry) -> ParsedSpec | None:
            try:
                text = self.fetch_raw(branch, entry.path)
                return parse_spec(
                    text,
                    branch=branch,
                    path=entry.path,
                    present_files=present,
                    raw_url=self.raw_url(branch, entry.path),
                )
            except Exception:  # pragma: no cover - defensive; keep scanning
                return None

        with ThreadPoolExecutor(max_workers=config.SCAN_CONCURRENCY) as pool:
            futures = {pool.submit(work, e): e for e in entries}
            done = 0
            for fut in as_completed(futures):
                spec = fut.result()
                done += 1
                if spec and spec.name:
                    specs.append(spec)
                if progress and done % 50 == 0:
                    progress(done, len(entries))

        specs.sort(key=lambda s: s.name.lower())
        return specs


def blob_tarball_url(filename: str) -> str:
    return f"{config.BLOB_STORE_BASE}/{filename}"


def check_blob_exists(filename: str, session: requests.Session | None = None) -> bool:
    """HEAD-check whether a tarball exists in the Azure Linux blob store."""
    if not filename:
        return False
    cache_dir = config.CACHE_DIR / "blobs"
    cache_dir.mkdir(parents=True, exist_ok=True)
    safe = filename.replace("/", "_")
    cache = cache_dir / safe
    if cache.exists():
        return cache.read_text().strip() == "1"
    sess = session or requests.Session()
    try:
        resp = sess.head(
            blob_tarball_url(filename),
            timeout=config.HTTP_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": config.user_agent()},
        )
        ok = resp.status_code == 200
    except requests.RequestException:
        ok = False
    cache.write_text("1" if ok else "0")
    return ok
