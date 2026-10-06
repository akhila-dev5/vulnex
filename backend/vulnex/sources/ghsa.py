"""GitHub Security Advisories (GHSA) source.

Queried by CVE id through the public ``/advisories`` endpoint. Useful for
severity and for locating the upstream fix commit referenced by an advisory.
"""

from __future__ import annotations

from .. import config
from ..cvss import normalise_severity
from ..http import CachedHTTP

__all__ = ["GHSASource"]


class GHSASource:
    name = "ghsa"

    def __init__(self, session=None):
        self.http = CachedHTTP("ghsa", session)
        token = config.github_token()
        self.headers = {"Accept": "application/vnd.github+json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def fetch(self, cve_id: str) -> dict | None:
        data = self.http.get_json(
            f"{config.GITHUB_API}/advisories",
            key=cve_id,
            params={"cve_id": cve_id},
            headers=self.headers,
        )
        if not data:
            return None
        items = data if isinstance(data, list) else data.get("items") or []
        if not items:
            return None
        adv = items[0]
        cvss = adv.get("cvss") or {}
        score = cvss.get("score")
        if score is not None:
            try:
                score = float(score)
            except (TypeError, ValueError):
                score = None
        references = [
            {"type": "ghsa-ref", "url": r.get("url", "")} for r in adv.get("references") or []
        ]
        return {
            "source": self.name,
            "severity": normalise_severity(adv.get("severity")),
            "cvss_score": score,
            "cvss_vector": cvss.get("vector_string", ""),
            "description": adv.get("description", "") or adv.get("summary", ""),
            "published": (adv.get("published_at") or "")[:10],
            "fixed_versions": [],
            "package_state": [],
            "references": references,
            "upstream_fix": (adv.get("references") or [{}])[0].get("url"),
            "ghsa_id": adv.get("ghsa_id", ""),
        }
