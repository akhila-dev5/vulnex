#!/usr/bin/env python3
"""Seed test data and record the API's answers as golden files.

The .NET integration tests (api/Vulnex.Api.Tests) start the API against a database holding
exactly the rows created by ``seed`` and compare every read endpoint with the files in
``api/Vulnex.Api.Tests/golden``. The golden files were first recorded from the original
Python API, so they pin the behaviour the migration had to keep.

    DATABASE_URL=postgresql://... python scripts/api_snapshots.py seed
    DATABASE_URL=postgresql://... python scripts/api_snapshots.py record --base http://127.0.0.1:8000

``record`` overwrites the golden files from whatever server answers at --base; only use it
when an endpoint is *meant* to change, and review the diff.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

# Keys whose values legitimately differ between runs (the .NET tests drop the same keys).
VOLATILE = {
    "time", "expires_at", "_fetched_at",
    # stamped with the clock when the test rows are seeded, so they differ on every run
    "created_at", "updated_at", "first_seen", "rescored_at", "started_at", "finished_at", "requested_at",
}


def seed() -> None:
    from vulnex import db

    conn = db.connect()
    db.init_db(conn)
    conn.execute(
        "TRUNCATE scans, packages, patches, findings, assignments, assignment_comments, finding_triage, "
        "finding_comments, disputes, cve_rescores, automation_requests, cve_cache RESTART IDENTITY"
    )
    conn.commit()

    scan_id = db.start_scan(conn, ["3.0", "4.0"], "Azure Linux:3+Azure Linux:4")

    def package(name, branch, version="1.2.3", primary=1, tarball=True):
        return dict(
            scan_id=scan_id, branch=branch, name=name, version=version, release="2", epoch=0,
            evr=f"{version}-2", summary=f"{name} summary", license="MIT", url=f"https://example.org/{name}",
            group_name="Applications", spec_path=f"SPECS/{name}/{name}.spec",
            spec_url=f"https://github.com/akhila-dev5/azurelinux-test/blob/{branch}/SPECS/{name}/{name}.spec",
            source0_url=f"https://example.org/{name}-{version}.tar.gz",
            source_urls=json.dumps([f"https://example.org/{name}-{version}.tar.gz"]),
            tarball_name=f"{name}-{version}.tar.gz" if tarball else None,
            tarball_url=f"https://blob/{name}-{version}.tar.gz" if tarball else None,
            tarball_available=1 if tarball else None, patch_count=1, is_primary=primary,
        )

    def patch(name, branch, tag, filename, cves, nopatch=0):
        return dict(
            scan_id=scan_id, package_name=name, branch=branch, spec_path=f"SPECS/{name}/{name}.spec",
            tag=tag, filename=filename, cve_ids=json.dumps(cves), is_nopatch=nopatch,
            file_present=1, status="applied", comment=None,
        )

    def finding(cve, name, branch, status, severity, **extra):
        base = dict(
            scan_id=scan_id, cve_id=cve, package_name=name, package_version="1.2.3-2", branch=branch,
            spec_path=f"SPECS/{name}/{name}.spec", status=status, severity=severity, cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", confidence=0.9,
            description=f"{cve} in {name}", fixed_version="1.2.4", advisory_id=f"ADV-{cve}", source="osv",
            refs=json.dumps([{"url": f"https://github.com/o/{name}/commit/abc{cve[-1]}", "source": "osv"},
                             {"url": "https://example.org/advisory", "source": "nvd"}]),
            upstream_fix=f"https://github.com/o/{name}/commit/abc{cve[-1]}", patch_name=None,
            patch_status=None, fixed_in=None, fixed_in_basis=None, fix_source=None,
            affected_files=json.dumps(["src/a.c", "src/b.c"]), corroborating_sources=json.dumps(["debian"]),
            evidence=json.dumps([{"kind": "version", "detail": "1.2.3 < 1.2.4"}]), raw_sources=json.dumps([]),
        )
        base.update(extra)
        return base

    packages = [
        package("alpha", "3.0"), package("alpha", "4.0", "2.0.0"), package("beta", "3.0", tarball=False),
        package("golang", "3.0", "1.24.1"), package("golang-1.22", "3.0", "1.22.9", primary=0),
    ]
    patches = [
        patch("alpha", "3.0", "Patch0", "CVE-2024-0003.patch", ["CVE-2024-0003"]),
        patch("beta", "3.0", "Patch1", "CVE-2024-0004.nopatch", ["CVE-2024-0004"], nopatch=1),
    ]
    findings = [
        finding("CVE-2024-0001", "alpha", "3.0", "affected", "critical", first_seen="2026-01-02T00:00:00+00:00"),
        finding("CVE-2024-0001", "alpha", "4.0", "affected", "critical"),
        finding("CVE-2024-0002", "beta", "3.0", "affected", "high", upstream_fix=None, refs=json.dumps([])),
        finding("CVE-2024-0003", "alpha", "3.0", "patched", "medium", patch_name="CVE-2024-0003.patch",
                patch_status="applied", fixed_in="1.2.3-2", fixed_in_basis="changelog", fix_source="patch"),
        finding("CVE-2024-0004", "beta", "3.0", "false_positive", "low", patch_name="CVE-2024-0004.nopatch"),
        finding("CVE-2024-0005", "golang", "3.0", "unconfirmed", "medium"),
        finding("CVE-2024-0006", "golang-1.22", "3.0", "affected", "low", cvss_score=None),
    ]
    db.replace_snapshot(conn, scan_id, packages, patches, findings, branches=None)
    db.finish_scan(conn, scan_id, status="success", message="seed",
                   counts={"packages": 5, "findings": 7, "affected": 4, "patched": 1}, duration=1.5)

    spec = "SPECS/alpha/alpha.spec"
    db.upsert_triage(conn, "CVE-2024-0001", "3.0", spec, owner="dev1.vulnex@gmail.com",
                     triage_status="open", resolution_status="in_progress",
                     github_pr_number="7", github_pr_url="https://github.com/akhila-dev5/azurelinux-test/pull/7",
                     github_pr_set_by="gurujuakhila.dev@gmail.com", github_pr_set_at="2026-02-01T00:00:00+00:00")
    db.upsert_triage(conn, "CVE-2024-0002", "3.0", "SPECS/beta/beta.spec", final_verdict="Patch Available",
                     patch_link="https://example.org/fix.patch", available_since="2026-01-01")
    db.add_finding_comment(conn, "CVE-2024-0001", "3.0", spec, "looks real", "gurujuakhila.dev@gmail.com")
    a = db.create_assignment(conn, "CVE-2024-0001", "alpha", "akhila-dev5/azurelinux-test", "please fix",
                             "vulnexsecurityautomation@gmail.com")
    db.add_comment(conn, a["id"], "on it", "gurujuakhila.dev@gmail.com")
    db.create_assignment(conn, "CVE-2024-0002", "beta", "akhila-dev5/azurelinux-test", "", "dev2.vulnex@gmail.com")
    f = db.get_finding_at(conn, "CVE-2024-0002", "3.0", "SPECS/beta/beta.spec")
    db.create_dispute(conn, f, "not reachable", "dev1.vulnex@gmail.com", first_unaffected_version="1.0")
    db.set_rescore(conn, "CVE-2024-0006", "high", 8.1, "exploit exists", "gurujuakhila.dev@gmail.com")
    db.cache_cve(conn, "CVE-2024-0001", {
        "cve_id": "CVE-2024-0001", "cvss_score": 9.8, "severity": "critical", "published": "2024-01-05T10:00:00",
        "references": [{"url": "https://example.org/x.patch", "source": "nvd"}],
    })
    db.create_automation_request(conn, "alpha", "3.0", spec, ["CVE-2024-0001"], "new_pr", "", "x@example.org")
    conn.close()


CHECKS = [
    "/api/role",
    "/api/stats", "/api/stats?branch=3.0", "/api/stats?branch=4.0", "/api/stats?branch=9.9",
    "/api/packages", "/api/packages?branch=3.0&limit=2&page=2", "/api/packages?search=GOL",
    "/api/packages/alpha", "/api/packages/alpha?branch=4.0", "/api/packages/golang?spec=SPECS/golang-1.22/golang-1.22.spec",
    "/api/packages/nope",
    "/api/findings", "/api/findings?branch=3.0", "/api/findings?severity=critical", "/api/findings?status=patched",
    "/api/findings?search=beta", "/api/findings?package=alpha&branch=3.0", "/api/findings?patch_state=available",
    "/api/findings?patch_state=unavailable", "/api/findings?owner=dev1", "/api/findings?triage_status=open",
    "/api/findings?resolution_status=in_progress", "/api/findings?fixed_version=1.2.3", "/api/findings?limit=2&page=2",
    "/api/cves/CVE-2024-0001?enrich=false", "/api/cves/cve-2024-0006?enrich=false", "/api/cves/CVE-2024-0003?enrich=false",
    "/api/cves/CVE-9999-0000?enrich=false",
    "/api/cves/CVE-2024-0001/deep", "/api/cves/CVE-2024-0003/deep?branch=3.0&spec=SPECS/alpha/alpha.spec",
    "/api/cves/CVE-9999-0000/deep",
    "/api/triage", "/api/triage?search=alpha&limit=1",
    "/api/triage/comments?cve_id=CVE-2024-0001&branch=3.0&spec_path=SPECS/alpha/alpha.spec",
    "/api/disputes", "/api/disputes?status=pending", "/api/disputes?status=bogus",
    "/api/assignments", "/api/scans",
]


def get(base: str, path: str):
    req = urllib.request.Request(base + path)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, body


def clean(value):
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, float) and value == int(value):
        return int(value)
    return value


def diff(a, b, path="$"):
    if type(a) is not type(b) and not (isinstance(a, (int, float)) and isinstance(b, (int, float))
                                       and not isinstance(a, bool) and not isinstance(b, bool)):
        yield f"{path}: python={a!r:.120} dotnet={b!r:.120}"
    elif isinstance(a, dict):
        for key in sorted(set(a) | set(b)):
            if key not in a:
                yield f"{path}.{key}: only in dotnet ({b[key]!r:.80})"
            elif key not in b:
                yield f"{path}.{key}: only in python ({a[key]!r:.80})"
            else:
                yield from diff(a[key], b[key], f"{path}.{key}")
    elif isinstance(a, list):
        if len(a) != len(b):
            yield f"{path}: list length python={len(a)} dotnet={len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            yield from diff(x, y, f"{path}[{i}]")
    elif a != b:
        yield f"{path}: python={a!r:.120} dotnet={b!r:.120}"


def record(base: str, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.json"):
        old.unlink()
    for i, path in enumerate(CHECKS, start=1):
        status, body = get(base, path)
        (out / f"{i:03d}.json").write_text(
            json.dumps({"path": path, "status": status, "body": clean(body)}, indent=1, sort_keys=True) + "\n"
        )
    print(f"recorded {len(CHECKS)} endpoints into {out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["seed", "record"])
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "api" / "Vulnex.Api.Tests" / "golden"))
    args = parser.parse_args()
    if not os.environ.get("DATABASE_URL"):
        print("DATABASE_URL must point at the PostgreSQL test database", file=sys.stderr)
        return 2
    if args.command == "seed":
        seed()
        print("seeded")
        return 0
    return record(args.base, Path(args.out))


if __name__ == "__main__":
    sys.exit(main())
