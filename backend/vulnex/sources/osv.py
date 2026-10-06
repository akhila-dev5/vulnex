"""OSV.dev vulnerability source.

OSV hosts the **official Microsoft Azure Linux advisory database** under the
``Azure Linux:<major>`` ecosystem (imported from
``microsoft/AzureLinuxVulnerabilityData``). Each advisory carries RPM
version-release ``fixed`` events such as ``1.3.1-1``, which lets VULNEX do real
version-range matching instead of keyword matching.

OSV is also used to corroborate CVE identifiers against other distributions
(Red Hat, Debian, Ubuntu, Alpine), all of which OSV imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cmp_to_key

from .. import config
from ..cvss import score_from_vector, severity_from_score
from ..http import CachedHTTP
from ..rpmvercmp import compare_evr
from ..spec_parser import extract_cve_ids

__all__ = ["OSVSource", "OSVAdvisory", "evaluate_events"]

_FIX_URL_HINTS = ("/commit/", "/pull/", "github.com/advisories", "/releases/tag", "/commit/")


@dataclass
class OSVAdvisory:
    """Normalised view of an OSV advisory."""

    id: str
    ecosystem: str
    cve_ids: list[str] = field(default_factory=list)
    summary: str = ""
    details: str = ""
    severity_vector: str = ""
    severity: str = "unknown"
    cvss_score: float | None = None
    references: list[dict] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    upstream: list[str] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    affected: bool = False
    fixed_version: str | None = None
    introduced: str | None = None
    source_url: str = ""
    published: str = ""
    modified: str = ""
    raw: dict = field(default_factory=dict)

    @property
    def upstream_fix(self) -> str | None:
        for ref in self.references:
            url = ref.get("url", "")
            if any(hint in url for hint in _FIX_URL_HINTS):
                return url
        return None


def _affected_entry(raw: dict, ecosystem: str) -> dict | None:
    """Pick the affected[] entry matching the Azure Linux ecosystem."""
    entries = raw.get("affected") or []
    for entry in entries:
        pkg = entry.get("package", {})
        if pkg.get("ecosystem") == ecosystem:
            return entry
    # Fall back to a purl/ecosystem substring match (e.g. "Azure Linux:2").
    for entry in entries:
        pkg = entry.get("package", {})
        purl = pkg.get("purl", "")
        if "azure-linux" in purl or "azure" in (pkg.get("ecosystem", "").lower()):
            return entry
    return entries[0] if entries else None


def _extract_events(entry: dict) -> list[dict]:
    events: list[dict] = []
    for rng in entry.get("ranges", []) or []:
        if rng.get("type") in ("ECOSYSTEM", "SEMVER", "RPM"):
            events.extend(rng.get("events", []))
    return events


def evaluate_events(events: list[dict], evr: str) -> tuple[bool, str | None, str | None]:
    """Evaluate OSV range events against an RPM EVR.

    Returns ``(affected, fixed_version, introduced)``. ``fixed_version`` is the
    first ``fixed`` boundary at or above ``evr`` (the minimal upgrade that
    resolves the finding).
    """
    affected = False
    introduced: str | None = None
    candidate_fixed: list[str] = []
    if not evr:
        return False, None, None

    for event in events:
        if "introduced" in event:
            boundary = event["introduced"]
            if boundary in ("0", ""):
                affected = True
                introduced = "0"
            elif compare_evr(evr, boundary) >= 0:
                affected = True
                introduced = boundary
            else:
                affected = False
                introduced = boundary
        elif "fixed" in event:
            boundary = event["fixed"]
            if compare_evr(evr, boundary) >= 0:
                affected = False
            else:
                if affected:
                    candidate_fixed.append(boundary)
        elif "last_affected" in event:
            boundary = event["last_affected"]
            if compare_evr(evr, boundary) > 0:
                affected = False

    fixed_version = None
    if candidate_fixed:
        fixed_version = min(candidate_fixed, key=cmp_to_key(compare_evr))
        # Ensure it is actually above evr.
        if compare_evr(fixed_version, evr) <= 0:
            fixed_version = None
    return affected, fixed_version, introduced


def parse_advisory(raw: dict, ecosystem: str, evr: str | None = None) -> OSVAdvisory:
    """Convert a raw OSV document into an :class:`OSVAdvisory`."""
    entry = _affected_entry(raw, ecosystem) or {}
    events = _extract_events(entry) if entry else []

    cve_ids: list[str] = []
    for source in list(raw.get("aliases") or []) + list(raw.get("upstream") or []):
        cve_ids.extend(extract_cve_ids(source))
    for ref in raw.get("references") or []:
        cve_ids.extend(extract_cve_ids(ref.get("url", "")))
    # de-dup, keep order
    seen: dict[str, None] = {}
    for cve in cve_ids:
        seen.setdefault(cve.upper(), None)
    cve_ids = list(seen)

    vector = ""
    score = None
    for sev in raw.get("severity") or []:
        if sev.get("type", "").startswith("CVSS_V3"):
            vector = sev.get("score", "")
            score = score_from_vector(vector)
            break

    advisory = OSVAdvisory(
        id=raw.get("id", ""),
        ecosystem=ecosystem,
        cve_ids=cve_ids,
        summary=raw.get("summary", ""),
        details=raw.get("details", ""),
        severity_vector=vector,
        severity=severity_from_score(score),
        cvss_score=score,
        references=raw.get("references") or [],
        aliases=raw.get("aliases") or [],
        upstream=raw.get("upstream") or [],
        events=events,
        source_url=(raw.get("database_specific") or {}).get("source", "")
        or f"https://osv.dev/vulnerability/{raw.get('id','')}",
        published=raw.get("published", ""),
        modified=raw.get("modified", ""),
        raw=raw,
    )
    if evr:
        affected, fixed, introduced = evaluate_events(events, evr)
        advisory.affected = affected
        advisory.fixed_version = fixed
        advisory.introduced = introduced
    return advisory


class OSVSource:
    """Thin client around the OSV API."""

    def __init__(self, session=None):
        self.http = CachedHTTP("osv", session)

    def query(self, name: str, ecosystem: str, version: str | None = None) -> list[dict]:
        body: dict = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            body["version"] = version
        key = f"{ecosystem}|{name}|{version or 'any'}"
        data = self.http.post_json(f"{config.OSV_API}/query", body, key)
        if not data:
            return []
        return data.get("vulns", []) or []

    def advisories(
        self, name: str, ecosystem: str, evr: str | None = None, version_filter: bool = True
    ) -> list[OSVAdvisory]:
        """Return all Azure Linux advisories for a package.

        When ``version_filter`` is true the query includes the EVR so OSV only
        returns advisories whose ranges match; the returned advisories are then
        re-evaluated locally by :func:`evaluate_events` for traceability.
        """
        raw = self.query(name, ecosystem, evr if version_filter else None)
        return [parse_advisory(item, ecosystem, evr) for item in raw]

    def corroborating_cves(self, name: str, ecosystems: list[str]) -> dict[str, list[str]]:
        """Map CVE id -> list of ecosystems corroborating it for ``name``."""
        out: dict[str, list[str]] = {}
        for eco in ecosystems:
            for item in self.query(name, eco):
                for cve in parse_advisory(item, eco).cve_ids:
                    out.setdefault(cve, [])
                    if eco not in out[cve]:
                        out[cve].append(eco)
        return out
