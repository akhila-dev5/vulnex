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
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
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
