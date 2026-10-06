"""MITRE CVE Services (CVE 5.x) source.

The CVE Program's own record is the authoritative CVE identity and often has a
description when NVD has not enriched the record yet.
"""

from __future__ import annotations

from .. import config
from ..http import CachedHTTP

__all__ = ["MITRESource"]


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
        return {
            "source": self.name,
            "severity": "unknown",
            "cvss_score": None,
            "cvss_vector": "",
            "description": description,
            "published": (cve_metadata.get("datePublished") or "")[:10],
            "fixed_versions": [],
            "package_state": [],
            "references": references,
            "upstream_fix": None,
        }
