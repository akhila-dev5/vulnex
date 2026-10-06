import json

from vulnex import config, db
from vulnex.export import export_site


def _seed(conn):
    scan_id = db.start_scan(conn, ["3.0-dev"], "Azure Linux:3")
    db.replace_snapshot(
        conn,
        scan_id,
        packages=[
            {
                "scan_id": scan_id,
                "branch": "3.0-dev",
                "name": "demo",
                "version": "1.2.3",
                "release": "4",
                "epoch": 0,
                "evr": "1.2.3-4",
                "summary": "Demo package",
                "license": "MIT",
                "url": "https://example.com",
                "group_name": "Libraries",
                "spec_path": "SPECS/demo/demo.spec",
                "spec_url": "https://raw/demo.spec",
                "source0_url": "https://example.com/demo-1.2.3.tar.gz",
                "source_urls": db.dumps([]),
                "tarball_name": "demo-1.2.3.tar.gz",
                "tarball_url": "https://blob/demo-1.2.3.tar.gz",
                "tarball_available": 1,
                "patch_count": 1,
                "is_primary": 1,
            }
        ],
        patches=[
            {
                "scan_id": scan_id,
                "package_name": "demo",
                "branch": "3.0-dev",
                "spec_path": "SPECS/demo/demo.spec",
                "tag": "Patch0",
                "filename": "CVE-2024-0001.patch",
                "cve_ids": db.dumps(["CVE-2024-0001"]),
                "is_nopatch": 0,
                "file_present": 1,
                "status": "applied",
                "comment": "",
            }
        ],
        findings=[
            {
                "scan_id": scan_id,
                "cve_id": "CVE-2024-0500",
                "package_name": "demo",
                "package_version": "1.2.3-4",
                "branch": "3.0-dev",
                "spec_path": "SPECS/demo/demo.spec",
                "status": "affected",
                "severity": "high",
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "confidence": 0.8,
                "description": "demo vuln",
                "fixed_version": "1.2.4-1",
                "advisory_id": "AZL-1",
                "source": "osv:Azure Linux:3",
                "refs": db.dumps([{"type": "WEB", "url": "https://example.com/fix"}]),
                "upstream_fix": None,
                "patch_name": None,
                "patch_status": None,
                "affected_files": db.dumps([]),
                "corroborating_sources": db.dumps(["Red Hat"]),
                "evidence": db.dumps(["RPM version match"]),
                "raw_sources": db.dumps(["osv"]),
            }
        ],
    )
    db.finish_scan(
        conn, scan_id, status="success",
        counts={"packages": 1, "findings": 1, "affected": 1},
    )


def test_export_writes_static_dashboard(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "vulnex.db")
    with db.session() as conn:
        _seed(conn)

    out = tmp_path / "site"
    summary = export_site(out, frontend_dir=config.FRONTEND_DIR)

    assert summary["packages"] == 1 and summary["findings"] == 1
    # Assets are copied and the entrypoint is flagged as a static snapshot.
    for asset in ("index.html", "app.js", "styles.css", "404.html"):
        assert (out / asset).exists()
    html = (out / "index.html").read_text(encoding="utf-8")
    assert "VULNEX_STATIC" in html
    assert "static-banner" in html

    stats = json.loads((out / "api" / "stats.json").read_text())
    assert stats["total_packages"] == 1
    assert stats["repository"]["repo"] == config.REPO_NAME

    findings = json.loads((out / "api" / "findings.json").read_text())
    assert len(findings) == 1
    # The `refs` column is rehydrated to `references` for the SPA.
    assert findings[0]["references"][0]["url"] == "https://example.com/fix"

    packages = json.loads((out / "api" / "packages.json").read_text())
    assert packages[0]["finding_counts"]["affected"] == 1

    patches = json.loads((out / "api" / "patches.json").read_text())
    assert patches[0]["cve_ids"] == ["CVE-2024-0001"]

    scans = json.loads((out / "api" / "scans.json").read_text())
    assert scans["latest"]["status"] == "success"
