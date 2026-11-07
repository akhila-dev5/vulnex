"""NVD (National Vulnerability Database) 2.0 API source.

NVD is the canonical CVSS authority. An API key (``NVD_API_KEY``) raises the
rate limit from 5 to 50 requests / 30 s; without one we simply fall back to
whatever the other sources provide.
"""

from __future__ import annotations

from .. import config
from ..http import CachedHTTP

__all__ = ["NVDSource"]


def _pick_metric(metrics: dict) -> tuple[str, float | None, str]:
    """Choose the CVSS score to show.

    NVD often has no analysis of its own yet ("NVD assessment not yet provided")
    while CISA-ADP or the CNA already scored the CVE; those entries are marked
    ``Secondary`` and used to be skipped past. Order: CVSS 3.1, 3.0, 4.0, 2.0,
    and inside each version NVD's own (``Primary``) entry before a secondary one.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = sorted(metrics.get(key) or [], key=lambda e: e.get("type") != "Primary")
        for entry in entries:
            data = entry.get("cvssData", {})
            vector = data.get("vectorString", "")
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or entry.get("baseSeverity") or ""
            if score is not None:
                return vector, float(score), str(sev).lower()
    return "", None, ""


class NVDSource:
    name = "nvd"

    def __init__(self, session=None):
        self.http = CachedHTTP("nvd", session)

    def fetch(self, cve_id: str) -> dict | None:
        headers = {}
        if config.NVD_API_KEY:
            headers["apiKey"] = config.NVD_API_KEY
        data = self.http.get_json(
            config.NVD_API,
            key=cve_id,
            params={"cveId": cve_id},
            headers=headers or None,
        )
        if not data:
            return None
        items = data.get("vulnerabilities") or []
        if not items:
            return None
        cve = items[0].get("cve", {})
        description = ""
        for desc in cve.get("descriptions") or []:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        vector, score, severity = _pick_metric(cve.get("metrics") or {})
        weaknesses = []
        for w in cve.get("weaknesses") or []:
            for d in w.get("description") or []:
                if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                    weaknesses.append(d["value"])
        references = [
            {"type": "nvd-ref", "url": r.get("url", "")} for r in cve.get("references") or []
        ]
        return {
            "source": self.name,
            "severity": severity or "unknown",
            "cvss_score": score,
            "cvss_vector": vector,
            "description": description,
            "published": cve.get("published", "")[:10],
            "fixed_versions": [],
            "package_state": [],
            "weaknesses": sorted(set(weaknesses)),
            "references": references,
            "upstream_fix": None,
        }
