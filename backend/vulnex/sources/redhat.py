"""Red Hat Security Data API source.

Red Hat's severity taxonomy ("Important") and its RPM ``fixed_in`` package
versions are useful corroboration for an RPM-based distro like Azure Linux.
"""

from __future__ import annotations

from .. import config
from ..cvss import normalise_severity, score_from_vector
from ..http import CachedHTTP

__all__ = ["RedHatSource"]


class RedHatSource:
    name = "redhat"

    def __init__(self, session=None):
        self.http = CachedHTTP("redhat", session)

    def fetch(self, cve_id: str) -> dict | None:
        data = self.http.get_json(
            f"{config.REDHAT_SECURITY_API}/cve/{cve_id}.json", key=cve_id
        )
        if not data:
            return None

        severity = normalise_severity(data.get("threat_severity"))
        vector = ""
        score = None
        cvss3 = data.get("cvss3") or {}
        if cvss3 and cvss3.get("status") != "unaffected":
            vector = cvss3.get("cvss3_scoring_vector", "") or ""
            score = cvss3.get("cvss3_base_score")
            if score is not None:
                try:
                    score = float(score)
                except (TypeError, ValueError):
                    score = None
            if score and severity == "unknown":
                from ..cvss import severity_from_score

                severity = severity_from_score(score)
        elif vector:
            score = score_from_vector(vector)

        fixed: list[dict] = []
        for rel in data.get("affected_release") or []:
            pkg = rel.get("package", "")
            ver = pkg.split("-", 1)[0] if "-" in pkg else ""
            fixed.append(
                {
                    "product": rel.get("product_name", ""),
                    "package": pkg,
                    "version": ver,
                    "advisory": rel.get("advisory", ""),
                    "date": (rel.get("release_date") or "")[:10],
                }
            )

        states = [
            {
                "product": s.get("product_name", ""),
                "package": s.get("package_name", ""),
                "fix_state": s.get("fix_state", ""),
            }
            for s in data.get("package_state") or []
        ]

        bugzilla = data.get("bugzilla") or {}
        references = []
        if bugzilla.get("url"):
            references.append({"type": "bugzilla", "url": bugzilla["url"]})

        return {
            "source": self.name,
            "severity": severity,
            "cvss_score": score,
            "cvss_vector": vector,
            "description": bugzilla.get("description", "") or data.get("details", ""),
            "published": (data.get("public_date") or "")[:10],
            "fixed_versions": fixed,
            "package_state": states,
            "references": references,
            "upstream_fix": None,
        }
