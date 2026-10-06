"""Finding verification and confidence scoring.

This is the part that stops VULNEX from being a keyword matcher. A finding is
only "affected" when a version-range match agrees with the spec's own backport
state; distro patches and ``.nopatch`` markers explicitly override a naive
"version < fixed" conclusion.

Statuses
--------
``patched``
    The CVE is addressed by an applied ``Patch:`` in the ``.spec`` file, or the
    advisory is present but the distro has backported the fix.
``false_positive``
    The spec ships a ``CVE-*.nopatch`` marker: Azure Linux has explicitly
    assessed the CVE as not applicable to this package.
``affected``
    A version-range match says the package is vulnerable and no backport exists.
``unconfirmed``
    An advisory mentions the package but range/version data is insufficient to
    confirm exploitability. Flagged for human review.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .sources.osv import OSVAdvisory
from .spec_parser import ParsedSpec, PatchItem

__all__ = ["Finding", "build_findings_for_package", "STATUS_AFFECTED", "STATUS_PATCHED",
           "STATUS_FALSE_POSITIVE", "STATUS_UNCONFIRMED"]

STATUS_AFFECTED = "affected"
STATUS_PATCHED = "patched"
STATUS_FALSE_POSITIVE = "false_positive"
STATUS_UNCONFIRMED = "unconfirmed"

_STATUS_BASE_CONFIDENCE = {
    STATUS_PATCHED: 0.90,
    STATUS_FALSE_POSITIVE: 0.92,
    STATUS_AFFECTED: 0.75,
    STATUS_UNCONFIRMED: 0.40,
}


@dataclass
class Finding:
    """A single CVE <-> package finding, with full provenance."""

    cve_id: str
    package_name: str
    package_version: str
    branch: str
    spec_path: str
    status: str
    severity: str = "unknown"
    cvss_score: float | None = None
    cvss_vector: str = ""
    confidence: float = 0.0
    description: str = ""
    fixed_version: str | None = None
    advisory_id: str | None = None
    source: str = ""
    references: list[dict] = field(default_factory=list)
    upstream_fix: str | None = None
    patch_name: str | None = None
    patch_status: str | None = None
    affected_files: list[str] = field(default_factory=list)
    corroborating_sources: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    raw_sources: list[str] = field(default_factory=list)


def _confidence(status: str, reasons: list[str], corroborating: list[str]) -> float:
    conf = _STATUS_BASE_CONFIDENCE.get(status, 0.4)
    if corroborating:
        conf += min(0.10 * len(corroborating), 0.15)
    if "patch-file-present" in reasons:
        conf += 0.05
    if "missing-patch-file" in reasons:
        conf -= 0.20
    if "unfixed" in reasons:
        conf -= 0.05
    return round(max(0.0, min(0.99, conf)), 2)


def build_findings_for_package(
    spec: ParsedSpec,
    advisories: list[OSVAdvisory],
    corroboration: dict[str, list[str]] | None = None,
) -> list[Finding]:
    """Combine spec backport state with advisories into verified findings."""
    corroboration = corroboration or {}
    findings: dict[str, Finding] = {}

    patch_by_cve = spec.patch_cves()
    nopatch_by_cve = spec.nopatch_cves()

    # 1. Findings derived from the spec's own patches (authoritative backports).
    for cve, patch in patch_by_cve.items():
        finding = _from_patch(spec, cve, patch, advisory=None, kind="patch")
        findings[cve] = finding
    for cve, patch in nopatch_by_cve.items():
        findings[cve] = _from_patch(spec, cve, patch, advisory=None, kind="nopatch")

    # 2. Findings derived from OSV Azure Linux advisories.
    for advisory in advisories:
        cves = advisory.cve_ids or [advisory.id]
        for cve in cves:
            cve = cve.upper()
            existing = findings.get(cve)
            if existing and existing.status in (STATUS_PATCHED, STATUS_FALSE_POSITIVE):
                # A backport/nopatch already settles this CVE; enrich provenance.
                existing.corroborating_sources = sorted(
                    set(existing.corroborating_sources) | set(corroboration.get(cve, []))
                )
                existing.raw_sources = sorted(set(existing.raw_sources) | {"osv"})
                if not existing.advisory_id:
                    existing.advisory_id = advisory.id
                if advisory.severity != "unknown" and existing.severity == "unknown":
                    existing.severity = advisory.severity
                    existing.cvss_score = advisory.cvss_score
                    existing.cvss_vector = advisory.severity_vector
                if not existing.description:
                    existing.description = advisory.details or advisory.summary
                if not existing.fixed_version:
                    existing.fixed_version = advisory.fixed_version
                if not existing.references:
                    existing.references = advisory.references
                if advisory.affected:
                    existing.evidence.append(
                        f"OSV {advisory.id} flags {spec.evr} as in-range, but the "
                        f"distro backport already addresses this CVE."
                    )
                continue
            findings[cve] = _from_advisory(spec, cve, advisory, patch_by_cve, corroboration)

    return list(findings.values())


def _from_patch(
    spec: ParsedSpec,
    cve: str,
    patch: PatchItem,
    advisory: OSVAdvisory | None,
    kind: str,
) -> Finding:
    reasons: list[str] = []
    if patch.file_present is True:
        reasons.append("patch-file-present")
    if patch.file_present is False:
        reasons.append("missing-patch-file")

    if kind == "nopatch":
        status = STATUS_FALSE_POSITIVE
        evidence = [
            f"{spec.name} ships {patch.filename}, an explicit 'not affected' marker "
            f"for {cve} in {spec.path}.",
        ]
        patch_status = "not-affected"
    else:
        status = STATUS_PATCHED
        evidence = [
            f"{spec.name} applies {patch.filename} ({patch.tag}) in {spec.path}, "
            f"backporting the fix for {cve}.",
        ]
        patch_status = patch.status

    if patch.file_present is False:
        evidence.append("Referenced patch file was not found in the repository tree.")

    finding = Finding(
        cve_id=cve,
        package_name=spec.name,
        package_version=spec.evr,
        branch=spec.branch,
        spec_path=spec.path,
        status=status,
        confidence=_confidence(status, reasons, []),
        description="",
        patch_name=patch.filename,
        patch_status=patch_status,
        source="spec-patch",
        evidence=evidence,
        raw_sources=["spec"],
    )
    if advisory:
        finding.advisory_id = advisory.id
        finding.severity = advisory.severity
        finding.cvss_score = advisory.cvss_score
        finding.cvss_vector = advisory.severity_vector
        finding.fixed_version = advisory.fixed_version
        finding.description = advisory.details
        finding.references = advisory.references
        finding.upstream_fix = advisory.upstream_fix
    return finding


def _from_advisory(
    spec: ParsedSpec,
    cve: str,
    advisory: OSVAdvisory,
    patch_by_cve: dict[str, PatchItem],
    corroboration: dict[str, list[str]],
) -> Finding:
    corroborating = list(corroboration.get(cve, []))
    reasons: list[str] = []
    evidence: list[str] = [
        f"OSV advisory {advisory.id} ({advisory.ecosystem}) covers {spec.name}.",
    ]

    if advisory.affected and advisory.fixed_version:
        status = STATUS_AFFECTED
        evidence.append(
            f"RPM version match: {spec.evr} is inside the affected range "
            f"(fixed in {advisory.fixed_version})."
        )
    elif advisory.affected and advisory.events:
        # Azure Linux advisories scope the range with last_affected = the exact
        # shipped version, i.e. the package is affected and no fix is published.
        status = STATUS_AFFECTED
        reasons.append("unfixed")
        evidence.append(
            f"RPM version match: {spec.evr} is within the affected range and no "
            f"fixed version is published yet (unfixed upstream/distro)."
        )
    else:
        status = STATUS_UNCONFIRMED
        evidence.append("Advisory mentions the package but no usable version range was found.")

    patch = patch_by_cve.get(cve)
    if status == STATUS_AFFECTED and patch is not None:
        # Should be caught upstream, but keep the invariant explicit.
        status = STATUS_PATCHED

    if corroborating:
        evidence.append(
            "Corroborated by: " + ", ".join(corroborating) + "."
        )

    confidence = _confidence(status, reasons, corroborating)

    return Finding(
        cve_id=cve,
        package_name=spec.name,
        package_version=spec.evr,
        branch=spec.branch,
        spec_path=spec.path,
        status=status,
        severity=advisory.severity,
        cvss_score=advisory.cvss_score,
        cvss_vector=advisory.severity_vector,
        confidence=confidence,
        description=advisory.details or advisory.summary,
        fixed_version=advisory.fixed_version,
        advisory_id=advisory.id,
        source="osv:" + advisory.ecosystem,
        references=advisory.references,
        upstream_fix=advisory.upstream_fix,
        patch_name=patch.filename if patch else None,
        patch_status=patch.status if patch else None,
        corroborating_sources=corroborating,
        evidence=evidence,
        raw_sources=["osv"] + corroborating,
    )
