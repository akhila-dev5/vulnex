"""VULNEX scan orchestrator.

Pipeline::

    Azure Linux repo  ->  SPECS + patches    (azurelinux.py / spec_parser.py)
        ->  OSV Azure Linux advisories       (sources/osv.py)
        ->  version-range matching           (rpmvercmp.py / osv.evaluate_events)
        ->  verification + confidence        (verification.py)
        ->  corroboration + enrichment       (sources/*, enrichment.py)
        ->  SQLite snapshot                  (db.py)

The scanner is deliberately dependency-light and runs to completion in CI with
no paid services.
"""

from __future__ import annotations

import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import config, db
from .azurelinux import AzureLinuxRepo, check_blob_exists
from .enrichment import CVESources, enrich_cve, github_commit_files
from .rpmvercmp import compare_evr
from .sources.osv import OSVSource
from .spec_parser import ParsedSpec
from .verification import Finding, build_findings_for_package

__all__ = ["ScanOptions", "run_scan"]


@dataclass
class ScanOptions:
    branches: list[str] = field(default_factory=lambda: list(config.DEFAULT_BRANCHES))
    packages: set[str] | None = None
    limit: int = 0
    ecosystem: str = config.OSV_ECOSYSTEM
    include_extended: bool = False
    verify_blobs: bool = True
    corroborate: bool = True
    enrich: bool = True
    enrich_limit: int = 400
    commit_files_limit: int = 60
    owner: str | None = None
    repo: str | None = None


def _primary_spec_paths(specs: list[ParsedSpec]) -> set[str]:
    """Pick the canonical spec per (branch, package name).

    A package can be built from several spec files (``golang.spec`` plus
    ``golang-1.23.spec`` ... ). The canonical one is the unversioned
    ``<name>.spec``; otherwise the newest EVR wins. Everything else is kept as a
    non-primary variant so no spec is lost.
    """
    groups: dict[tuple[str, str], list[ParsedSpec]] = {}
    for spec in specs:
        groups.setdefault((spec.branch, spec.name), []).append(spec)

    primaries: set[str] = set()
    for (_, name), group in groups.items():
        canonical = [s for s in group if s.path.rsplit("/", 1)[-1] == f"{name}.spec"]
        if canonical:
            primaries.add(canonical[0].path)
        else:
            newest = max(group, key=lambda s: compare_evr(s.evr or "0", "0"))
            primaries.add(newest.path)
    return primaries


def _package_row(
    spec: ParsedSpec,
    scan_id: int,
    tarball_available: bool | None,
    is_primary: bool = True,
) -> dict:
    primary = spec.primary_source
    source_urls = [
        {
            "tag": s.tag,
            "url": s.url,
            "filename": s.filename,
            "is_tarball": s.is_tarball,
            "blob_url": s.blob_url,
        }
        for s in spec.sources
    ]
    tarball_name = primary.filename if primary and primary.is_tarball else None
    tarball_url = primary.blob_url if primary and primary.is_tarball else None
    return {
        "scan_id": scan_id,
        "branch": spec.branch,
        "name": spec.name,
        "version": spec.version,
        "release": spec.release,
        "epoch": spec.epoch,
        "evr": spec.evr,
        "summary": spec.summary,
        "license": spec.license,
        "url": spec.url,
        "group_name": spec.group,
        "spec_path": spec.path,
        "spec_url": spec.raw_url,
        "source0_url": primary.url if primary else None,
        "source_urls": db.dumps(source_urls),
        "tarball_name": tarball_name,
        "tarball_url": tarball_url,
        "tarball_available": None if tarball_available is None else int(tarball_available),
        "patch_count": len(spec.patches),
        "is_primary": 1 if is_primary else 0,
    }


def _patch_rows(spec: ParsedSpec, scan_id: int) -> list[dict]:
    rows = []
    for patch in spec.patches:
        rows.append(
            {
                "scan_id": scan_id,
                "package_name": spec.name,
                "branch": spec.branch,
                "spec_path": spec.path,
                "tag": patch.tag,
                "filename": patch.filename,
                "cve_ids": db.dumps(patch.cve_ids),
                "is_nopatch": int(patch.is_nopatch),
                "file_present": None if patch.file_present is None else int(patch.file_present),
                "status": patch.status,
                "comment": patch.comment[:2000],
            }
        )
    return rows


def _finding_row(finding: Finding, scan_id: int) -> dict:
    return {
        "scan_id": scan_id,
        "cve_id": finding.cve_id,
        "package_name": finding.package_name,
        "package_version": finding.package_version,
        "branch": finding.branch,
        "spec_path": finding.spec_path,
        "status": finding.status,
        "severity": finding.severity,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "confidence": finding.confidence,
        "description": finding.description,
        "fixed_version": finding.fixed_version,
        "advisory_id": finding.advisory_id,
        "source": finding.source,
        "refs": db.dumps(finding.references),
        "upstream_fix": finding.upstream_fix,
        "patch_name": finding.patch_name,
        "patch_status": finding.patch_status,
        "affected_files": db.dumps(finding.affected_files),
        "corroborating_sources": db.dumps(finding.corroborating_sources),
        "evidence": db.dumps(finding.evidence),
        "raw_sources": db.dumps(finding.raw_sources),
    }


def run_scan(
    conn: sqlite3.Connection,
    options: ScanOptions | None = None,
    progress=None,
) -> dict:
    """Run a full scan and persist a fresh snapshot. Returns scan counts."""
    options = options or ScanOptions()
    started = time.time()

    def emit(message: str, **extra) -> None:
        if progress:
            progress(message, **extra)

    scan_id = db.start_scan(conn, options.branches, options.ecosystem)
    try:
        repo = AzureLinuxRepo(owner=options.owner, repo=options.repo)
        osv = OSVSource()

        # 1. Collect specs from every requested branch.
        specs: list[ParsedSpec] = []
        for branch in options.branches:
            emit(f"Collecting SPECS from {options.owner or config.REPO_OWNER}/"
                 f"{options.repo or config.REPO_NAME}@{branch}")
            collected = repo.collect(
                branch,
                packages=options.packages,
                limit=options.limit,
                include_extended=options.include_extended,
            )
            emit(f"Parsed {len(collected)} spec files on {branch}")
            specs.extend(collected)

        if not specs:
            raise RuntimeError("No spec files were collected from the repository.")

        # 2. Query OSV Azure Linux advisories for each spec version.
        emit(f"Querying OSV '{options.ecosystem}' advisories for {len(specs)} packages")
        advisories_by_spec: dict[int, list] = {}
        index = {id(s): i for i, s in enumerate(specs)}

        def fetch_advisories(spec: ParsedSpec) -> list:
            if not spec.evr:
                return []
            return osv.advisories(spec.name, options.ecosystem, spec.evr)

        with ThreadPoolExecutor(max_workers=config.SCAN_CONCURRENCY) as pool:
            futures = {pool.submit(fetch_advisories, s): s for s in specs}
            done = 0
            for fut in as_completed(futures):
                spec = futures[fut]
                done += 1
                try:
                    advisories_by_spec[index[id(spec)]] = fut.result()
                except Exception:
                    advisories_by_spec[index[id(spec)]] = []
                if done % 200 == 0:
                    emit(f"Matched advisories for {done}/{len(specs)} packages")

        # 3. Corroborate CVEs across other distro ecosystems for hit packages.
        corroboration: dict[int, dict[str, list[str]]] = {}
        if options.corroborate:
            hit_specs = [
                s for s in specs if advisories_by_spec.get(index[id(s)])
            ]
            emit(f"Corroborating CVEs across {','.join(config.CORROBORATION_ECOSYSTEMS)}")

            def corroborate(spec: ParsedSpec):
                try:
                    return osv.corroborating_cves(spec.name, config.CORROBORATION_ECOSYSTEMS)
                except Exception:
                    return {}

            with ThreadPoolExecutor(max_workers=config.SCAN_CONCURRENCY) as pool:
                futures = {pool.submit(corroborate, s): s for s in hit_specs}
                for fut in as_completed(futures):
                    spec = futures[fut]
                    corroboration[index[id(spec)]] = fut.result()

        # 4. Verify and build findings.
        emit("Verifying findings and scoring confidence")
        package_findings: dict[int, list[Finding]] = {}
        all_findings: list[Finding] = []
        for spec in specs:
            i = index[id(spec)]
            findings = build_findings_for_package(
                spec,
                advisories_by_spec.get(i, []),
                corroboration.get(i, {}),
            )
            package_findings[i] = findings
            all_findings.extend(findings)

        # 5. Optionally verify that source tarballs really exist in the blob store.
        tarball_availability: dict[int, bool | None] = {}
        if options.verify_blobs:
            emit("Verifying source tarballs against the Azure Linux blob store")
            with ThreadPoolExecutor(max_workers=config.SCAN_CONCURRENCY) as pool:
                futures = {}
                for spec in specs:
                    primary = spec.primary_source
                    if primary and primary.is_tarball:
                        futures[pool.submit(check_blob_exists, primary.filename)] = spec
                for fut in as_completed(futures):
                    spec = futures[fut]
                    try:
                        tarball_availability[index[id(spec)]] = fut.result()
                    except Exception:
                        tarball_availability[index[id(spec)]] = None

        # 6. Enrich the highest-signal findings (description/severity/refs).
        if options.enrich:
            _enrich_findings(all_findings, options, emit)

        # 7. Persist snapshot.
        emit("Writing scan snapshot to SQLite")
        primaries = _primary_spec_paths(specs)
        packages = [
            _package_row(
                s,
                scan_id,
                tarball_availability.get(index[id(s)]),
                is_primary=s.path in primaries,
            )
            for s in specs
        ]
        patches = [row for s in specs for row in _patch_rows(s, scan_id)]
        finding_rows = [_finding_row(f, scan_id) for f in all_findings]
        db.replace_snapshot(conn, scan_id, packages, patches, finding_rows)

        counts = _tally(all_findings)
        counts["packages"] = len(specs)
        counts["findings"] = len(all_findings)
        db.finish_scan(
            conn,
            scan_id,
            status="success",
            message=(
                f"Scanned {len(specs)} packages across {len(options.branches)} branch(es); "
                f"{len(all_findings)} findings."
            ),
            counts=counts,
            duration=round(time.time() - started, 2),
        )
        emit("Scan complete", counts=counts)
        return {
            "scan_id": scan_id,
            "counts": counts,
            "duration_seconds": round(time.time() - started, 2),
        }
    except Exception as exc:  # pragma: no cover - surfaced to the caller/API
        db.finish_scan(
            conn, scan_id, status="failed", message=str(exc)[:500],
            duration=round(time.time() - started, 2),
        )
        raise


def _tally(findings: list[Finding]) -> dict[str, int]:
    out = {"affected": 0, "patched": 0, "false_positive": 0, "unconfirmed": 0}
    for f in findings:
        out[f.status] = out.get(f.status, 0) + 1
    return out


def _enrich_findings(findings: list[Finding], options: ScanOptions, emit) -> None:
    """Enrich unique CVEs, then push severity/description back into findings."""
    unique: dict[str, None] = {}
    for f in findings:
        if f.status in ("affected", "unconfirmed"):
            unique.setdefault(f.cve_id, None)
    cve_ids = list(unique)[: options.enrich_limit]
    if not cve_ids:
        return
    emit(f"Enriching {len(cve_ids)} CVEs from NVD/MITRE/Red Hat/GHSA")
    sources = CVESources()
    enriched: dict[str, dict] = {}

    def work(cve_id: str):
        try:
            return cve_id, enrich_cve(cve_id, sources)
        except Exception:
            return cve_id, None

    with ThreadPoolExecutor(max_workers=config.ENRICH_CONCURRENCY) as pool:
        futures = [pool.submit(work, cve) for cve in cve_ids]
        for fut in as_completed(futures):
            cve_id, data = fut.result()
            if data:
                enriched[cve_id] = data

    for f in findings:
        data = enriched.get(f.cve_id)
        if not data:
            continue
        if data.get("severity") and data["severity"] != "unknown":
            f.severity = data["severity"]
        if data.get("cvss_score") is not None:
            f.cvss_score = data["cvss_score"]
            f.cvss_vector = data.get("cvss_vector", "") or f.cvss_vector
        if data.get("description") and len(data["description"]) > len(f.description):
            f.description = data["description"]
        if data.get("references"):
            f.references = data["references"]
        if data.get("upstream_fix"):
            f.upstream_fix = data["upstream_fix"]
        for src in data.get("sources", []):
            if src not in f.raw_sources:
                f.raw_sources.append(src)

    # Best-effort affected-file resolution from upstream fix commits.
    if options.commit_files_limit:
        candidates = [
            f for f in findings
            if f.status == "affected" and f.upstream_fix and not f.affected_files
        ][: options.commit_files_limit]
        emit(f"Resolving affected files for {len(candidates)} upstream fixes")
        with ThreadPoolExecutor(max_workers=config.ENRICH_CONCURRENCY) as pool:
            futures = {pool.submit(github_commit_files, f.upstream_fix): f for f in candidates}
            for fut in as_completed(futures):
                finding = futures[fut]
                try:
                    finding.affected_files = fut.result() or []
                except Exception:
                    finding.affected_files = []
