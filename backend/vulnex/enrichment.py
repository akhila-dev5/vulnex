"""Cross-source CVE enrichment.

A single CVE is looked up across NVD, MITRE, Red Hat, GHSA and OSV. The result
is merged into one record that keeps *every* contributing source, so the
dashboard can always show where a severity, description or fix version came
from. Severity resolution prefers a numeric CVSS score (NVD first) and falls
back to vendor severity text.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from . import config
from .cvss import normalise_severity, severity_from_score
from .http import CachedHTTP
from .sources.ghsa import GHSASource
from .sources.mitre import MITRESource
from .sources.nvd import NVDSource
from .sources.redhat import RedHatSource

__all__ = ["enrich_cve", "github_commit_files", "CVESources"]

_COMMIT_URL_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")
_BRANCH_COMMIT_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/")

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "unknown": -1}


class CVESources:
    """Container for the enrichment source clients (reused across a scan)."""

    def __init__(self, session=None):
        self.nvd = NVDSource(session)
        self.mitre = MITRESource(session)
        self.redhat = RedHatSource(session)
        self.ghsa = GHSASource(session)

    def collect(self, cve_id: str) -> dict[str, dict]:
        """Fetch a CVE from every source concurrently."""

        def safe(fn, name):
            try:
                data = fn(cve_id)
            except Exception:
                data = None
            if data:
                data.setdefault("source", name)
            return name, data

        jobs = [
            (self.nvd.fetch, "nvd"),
            (self.mitre.fetch, "mitre"),
            (self.redhat.fetch, "redhat"),
            (self.ghsa.fetch, "ghsa"),
        ]
        out: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=4) as pool:
            for name, data in pool.map(lambda job: safe(*job), jobs):
                if data:
                    out[name] = data
        return out


def _best_severity(results: dict[str, dict]) -> tuple[str, float | None, str]:
    """Pick the most authoritative severity/score across sources."""
    score = None
    vector = ""
    # Prefer a numeric score; NVD first, then Red Hat, then GHSA.
    for name in ("nvd", "redhat", "ghsa", "mitre"):
        item = results.get(name)
        if item and item.get("cvss_score"):
            score = item["cvss_score"]
            vector = item.get("cvss_vector", "")
            break
    if score is not None:
        return severity_from_score(score), score, vector

    # Otherwise take the highest textual severity reported.
    best = "unknown"
    for name in ("nvd", "redhat", "ghsa", "mitre"):
        item = results.get(name)
        if not item:
            continue
        sev = normalise_severity(item.get("severity"))
        if _SEVERITY_ORDER.get(sev, -1) > _SEVERITY_ORDER.get(best, -1):
            best = sev
    return best, None, vector


def enrich_cve(cve_id: str, sources: CVESources | None = None) -> dict:
    """Return a merged enrichment record for ``cve_id``."""
    sources = sources or CVESources()
    results = sources.collect(cve_id)
    severity, score, vector = _best_severity(results)

    description = ""
    for name in ("nvd", "mitre", "redhat", "ghsa"):
        item = results.get(name)
        if item and item.get("description"):
            description = item["description"]
            break

    published = ""
    for name in ("nvd", "mitre", "ghsa", "redhat"):
        item = results.get(name)
        if item and item.get("published"):
            published = item["published"]
            break

    references: list[dict] = []
    seen_urls: set[str] = set()
    upstream_fix = None
    for name in ("nvd", "ghsa", "mitre", "redhat"):
        item = results.get(name)
        if not item:
            continue
        if not upstream_fix and item.get("upstream_fix"):
            upstream_fix = item["upstream_fix"]
        for ref in item.get("references", []):
            url = ref.get("url")
            if url and url not in seen_urls:
                seen_urls.add(url)
                references.append({"source": name, **ref})
    if not upstream_fix:
        for ref in references:
            if "/commit/" in ref.get("url", ""):
                upstream_fix = ref["url"]
                break

    fixed_versions: list[dict] = []
    for name in ("redhat",):
        item = results.get(name)
        if item:
            fixed_versions.extend(item.get("fixed_versions", []))

    weaknesses: list[str] = []
    for item in results.values():
        weaknesses.extend(item.get("weaknesses", []))

    return {
        "cve_id": cve_id,
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "description": description,
        "published": published,
        "references": references,
        "upstream_fix": upstream_fix,
        "fixed_versions": fixed_versions,
        "weaknesses": sorted(set(weaknesses)),
        "sources": sorted(results.keys()),
        "source_data": results,
    }


def github_commit_files(url: str | None) -> list[str]:
    """Return the list of files touched by a GitHub commit URL.

    Used to populate the "affected files" column for CVEs that have an upstream
    fix commit reference. Best-effort and cached.
    """
    if not url:
        return []
    match = _COMMIT_URL_RE.search(url)
    if not match:
        return []
    owner, repo, sha = match.groups()
    http = CachedHTTP("github_commit")
    headers = {"Accept": "application/vnd.github+json"}
    token = config.github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = http.get_json(
        f"{config.GITHUB_API}/repos/{owner}/{repo}/commits/{sha}",
        key=f"{owner}-{repo}-{sha}",
        headers=headers,
    )
    if not data:
        return []
    files = []
    for f in data.get("files", []):
        name = f.get("filename")
        if name:
            files.append(name)
    # Also include parent-diff file headers as a fallback.
    return files
