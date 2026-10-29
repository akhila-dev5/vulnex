"""Reading-side triage helpers.

Three derived views are attached to every finding so the dashboard can render
them without a second round trip (and the static Pages export can bake them in):

``links``
    Deterministic per-CVE links to the well-known trackers (Ubuntu, Debian,
    Red Hat, MITRE, OSV, NVD). Always constructible, no network needed.

``patch_availability``
    The "Patch Available" panel: an AI verdict, the candidate **upstream** patch
    links and the date the fix became available. It only applies to a CVE this
    distro still has not fixed (an ``affected`` finding) — once the distro ships
    a backport the finding is ``patched`` and the site does not show it at all.
    The candidate links are upstream sources only (the upstream fix commit and
    patchable upstream advisory references); a distro backport file is never
    presented as an available patch.

``deep``
    What the **Deep** button shows: the files a CVE touches inside the package's
    source tarball (from the upstream fix commit) plus the distro backport patch
    files applied for that CVE.

All three are pure functions over data already in the snapshot, so a viewer can
read them and the numbers never drift from what the scanner stored.
"""

from __future__ import annotations

import re
from typing import Any

from . import config

__all__ = [
    "website_links",
    "patch_availability",
    "deep_view",
    "decorate_finding",
]

_PATCH_URL_RE = re.compile(
    r"(/commit/|/pull/|\.diff($|\?)|\.patch($|\?)|patch-diff)", re.IGNORECASE
)

# Order mirrors the reference tool: Ubuntu -> Debian -> Red Hat -> Mitre -> OSV.
_TRACKERS = (
    ("Ubuntu", "https://ubuntu.com/security/{cve}"),
    ("Debian", "https://security-tracker.debian.org/tracker/{cve}"),
    ("Red Hat", "https://access.redhat.com/security/cve/{cve}"),
    ("Mitre", "https://www.cve.org/CVERecord?id={cve}"),
    ("OSV", "https://osv.dev/vulnerability/{cve}"),
    ("NVD", "https://nvd.nist.gov/vuln/detail/{cve}"),
)


def website_links(cve_id: str) -> list[dict]:
    """Source links for a CVE, in a stable order."""
    cve = (cve_id or "").upper()
    if not cve:
        return []
    return [
        {"label": label, "url": template.format(cve=cve)}
        for label, template in _TRACKERS
    ]


def _repo_blob(spec_path: str, branch: str, filename: str) -> str:
    """GitHub blob URL for a patch file sitting next to its spec."""
    if not spec_path or not filename:
        return ""
    directory = spec_path.rsplit("/", 1)[0] if "/" in spec_path else ""
    parts = [p for p in (directory, filename) if p]
    path = "/".join(parts)
    return (
        f"https://github.com/{config.REPO_OWNER}/{config.REPO_NAME}"
        f"/blob/{branch}/{path}"
    )


def _candidate_patch_links(finding: dict, enrichment: dict | None) -> list[str]:
    """Patch-looking URLs from the advisory references, upstream fix first."""
    urls: list[str] = []
    seen: set[str] = set()

    def add(url: Any) -> None:
        if not isinstance(url, str) or not url or url in seen:
            return
        if _PATCH_URL_RE.search(url):
            seen.add(url)
            urls.append(url)

    upstream = finding.get("upstream_fix")
    if upstream:
        add(upstream)
    references: list[dict] = []
    if enrichment and enrichment.get("references"):
        references = enrichment["references"]
    else:
        references = finding.get("references") or []
    for ref in references:
        add(ref.get("url"))
    return urls


def patch_availability(
    finding: dict, enrichment: dict | None = None, triage: dict | None = None
) -> dict:
    """Upstream patch availability for an *unfixed* finding.

    Applicable only while the CVE is still open (``status == "affected"``): a
    CVE the distro has already backported is ``patched`` and is not shown on the
    site at all. Candidates are upstream sources — the upstream fix commit and
    patchable upstream advisory references — never the distro backport file,
    which represents work that is already done rather than availability.
    """
    status = finding.get("status") or ""
    triage = triage or {}
    applicable = status == "affected"

    candidates = _candidate_patch_links(finding, enrichment)
    upstream_fix = finding.get("upstream_fix") or ""

    if upstream_fix:
        patch_link = upstream_fix
        source = "upstream-fix"
    elif candidates:
        patch_link = candidates[0]
        source = "upstream-reference"
    else:
        patch_link = ""
        source = "none"

    available = bool(patch_link)
    if not applicable:
        ai_verdict = "Not applicable"
    else:
        ai_verdict = "Patch Available" if available else "No Patch Found"

    published = (enrichment or {}).get("published") or finding.get("advisory_published") or ""
    available_since = published[:10] if (published and available) else ""

    final_verdict = triage.get("final_verdict") or ai_verdict
    override_link = triage.get("patch_link") or ""
    override_since = triage.get("available_since") or ""

    analysis = []
    if not applicable:
        analysis.append(
            f"Finding is '{status or 'unknown'}', not an open exposure — patch "
            "availability does not apply."
        )
    if upstream_fix:
        analysis.append(f"Upstream fix commit: {upstream_fix}")
    for url in candidates[:3]:
        if url != upstream_fix:
            analysis.append(f"Upstream advisory reference looks patchable: {url}")
    if finding.get("fixed_version"):
        analysis.append(
            f"Upstream fixed version {finding['fixed_version']} is not yet shipped on "
            f"{finding.get('branch') or 'this branch'}."
        )
    if not analysis:
        analysis.append(
            "No upstream fix commit or patchable upstream reference was found for this CVE."
        )

    return {
        "applicable": applicable,
        "available": available,
        "ai_verdict": ai_verdict,
        "final_verdict": final_verdict,
        "overridden": bool(triage.get("final_verdict")),
        "possible_links": candidates,
        "patch_link": override_link or patch_link,
        "available_since": override_since or available_since,
        "source": source,
        "analysis": analysis,
    }


def deep_view(finding: dict, package: dict | None = None) -> dict:
    """Files inside the package's source tarball that this CVE touches."""
    package = package or {}
    branch = finding.get("branch") or ""
    spec_path = finding.get("spec_path") or ""

    affected = list(finding.get("affected_files") or [])
    patch_name = finding.get("patch_name")
    backports = []
    if patch_name and not str(patch_name).endswith(".nopatch"):
        backports.append(
            {
                "filename": patch_name,
                "url": _repo_blob(spec_path, branch, patch_name),
                "present": finding.get("patch_file_present"),
            }
        )

    tarball = None
    if package.get("tarball_name"):
        tarball = {
            "name": package.get("tarball_name"),
            "url": package.get("tarball_url") or "",
            "available": package.get("tarball_available"),
        }

    notes = []
    if affected:
        notes.append(
            "Files listed are the paths touched by the upstream fix commit for this CVE."
        )
    else:
        notes.append(
            "No upstream fix commit was resolvable, so the touched files could not be "
            "listed from that source."
        )
    if tarball:
        notes.append(f"Source tarball for this package: {tarball['name']}.")
    else:
        notes.append("This package declares no source tarball in its .spec file.")

    return {
        "cve_id": finding.get("cve_id"),
        "package_name": finding.get("package_name"),
        "package_version": finding.get("package_version"),
        "branch": branch,
        "spec_path": spec_path,
        "spec_url": package.get("spec_url") or finding.get("spec_url") or "",
        "tarball": tarball,
        "affected_files": affected,
        "backport_patches": backports,
        "notes": notes,
    }


def decorate_finding(
    finding: dict,
    package: dict | None = None,
    enrichment: dict | None = None,
    include_links: bool = True,
) -> dict:
    """Attach the derived triage views to a finding payload (in place).

    ``include_links`` is off for the bulk static export: the tracker links are a
    pure function of the CVE id, so shipping them once per finding would bloat
    the snapshot for no reason (the SPA derives them client-side).
    """
    if include_links:
        finding["links"] = website_links(finding.get("cve_id", ""))
    finding["patch_availability"] = patch_availability(
        finding, enrichment, finding.get("triage")
    )
    finding["deep"] = deep_view(finding, package)
    return finding
