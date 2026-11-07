"""MITRE CVE Services (CVE 5.x) source.

The CVE Program's own record is the authoritative CVE identity and often has a
description when NVD has not enriched the record yet.
"""

from __future__ import annotations

from .. import config
from ..http import CachedHTTP

__all__ = ["MITRESource"]


_METRIC_KEYS = ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0")


def pick_cvss(containers: dict) -> tuple[str, float | None, str]:
    """Best CVSS score in a CVE 5 record: the CNA's own, then any ADP (e.g. CISA-ADP).

    The CVE Program record carries scores even while NVD has not analysed the CVE.
    """
    boxes = [containers.get("cna") or {}] + list(containers.get("adp") or [])
    for key in _METRIC_KEYS:
        for box in boxes:
            for metric in box.get("metrics") or []:
                data = metric.get(key)
                if not data or data.get("baseScore") is None:
                    continue
                try:
                    score = float(data["baseScore"])
                except (TypeError, ValueError):
                    continue
                return data.get("vectorString", ""), score, str(data.get("baseSeverity", "")).lower()
    return "", None, ""


class MITRESource:
    name = "mitre"

    def __init__(self, session=None):
        self.http = CachedHTTP("mitre", session)

    def fetch(self, cve_id: str) -> dict | None:
        data = self.http.get_json(f"{config.MITRE_CVE_API}/{cve_id}", key=cve_id)
        if not data:
            return None
        containers = data.get("containers") or {}
        cna = containers.get("cna") or {}
        description = ""
        for desc in cna.get("descriptions") or []:
            if desc.get("lang", "en").startswith("en"):
                description = desc.get("value", "")
                break

        references = []
        for ref in cna.get("references") or []:
            references.append({"type": "mitre-ref", "url": ref.get("url", "")})

        cve_metadata = data.get("cveMetadata") or {}
        vector, score, severity = pick_cvss(containers)
        return {
            "source": self.name,
            "severity": severity or "unknown",
            "cvss_score": score,
            "cvss_vector": vector,
            "description": description,
            "published": (cve_metadata.get("datePublished") or "")[:10],
            "fixed_versions": [],
            "package_state": [],
            "references": references,
            "upstream_fix": None,
        }
