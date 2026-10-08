import json

import pytest
from fastapi.testclient import TestClient

from vulnex import auth, config, db
from vulnex.api import app

# Writes need an admin sign-in now that the tool is read-only by default.
ADMIN_EMAIL = "lead@example.com"
ADMIN_PASSWORD = "correct horse battery staple"
ADMIN_PASSWORD_HASH = auth.hash_password(ADMIN_PASSWORD)


def _finding(**over):
    row = {
        "scan_id": 1,
        "cve_id": "CVE-2024-0500",
        "package_name": "demo",
        "package_version": "1.2.3-4",
        "branch": "3.0-dev",
        "spec_path": "SPECS/demo/demo.spec",
        "status": "affected",
        "severity": "high",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "confidence": 0.82,
        "description": "A demo vulnerability",
        "fixed_version": "1.2.4-1",
        "advisory_id": "AZL-1",
        "source": "osv:Azure Linux:3",
        "refs": json.dumps([{"type": "WEB", "url": "https://example.com/fix"}]),
        "upstream_fix": "https://github.com/example/demo/commit/abc1234",
        "patch_name": None,
        "patch_status": None,
        "affected_files": json.dumps(["src/demo.c"]),
        "corroborating_sources": json.dumps(["Red Hat"]),
        "evidence": json.dumps(["RPM version match"]),
        "raw_sources": json.dumps(["osv", "nvd"]),
    }
    row.update(over)
    return row


def _package(**over):
    row = {
        "scan_id": 1,
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
        "spec_url": "https://raw.githubusercontent.com/x/y/z/SPECS/demo/demo.spec",
        "source0_url": "https://example.com/demo-1.2.3.tar.gz",
        "source_urls": json.dumps(
            [
                {
                    "tag": "Source0",
                    "url": "https://example.com/demo-1.2.3.tar.gz",
                    "filename": "demo-1.2.3.tar.gz",
                    "is_tarball": True,
                    "blob_url": "https://blob/demo-1.2.3.tar.gz",
                }
            ]
        ),
        "tarball_name": "demo-1.2.3.tar.gz",
        "tarball_url": "https://blob/demo-1.2.3.tar.gz",
        "tarball_available": 1,
        "patch_count": 1,
        "is_primary": 1,
    }
    row.update(over)
    return row


def _patch(**over):
    row = {
        "scan_id": 1,
        "package_name": "demo",
        "branch": "3.0-dev",
        "spec_path": "SPECS/demo/demo.spec",
        "tag": "Patch0",
        "filename": "CVE-2024-0001.patch",
        "cve_ids": json.dumps(["CVE-2024-0001"]),
        "is_nopatch": 0,
        "file_present": 1,
        "status": "applied",
        "comment": "",
    }
    row.update(over)
    return row


@pytest.fixture(autouse=True)
def _clean_sessions():
    auth.sessions.clear()
    yield
    auth.sessions.clear()


@pytest.fixture()
def admin(client):
    """Signed-in admin headers from the email + password endpoint."""
    resp = client.post(
        "/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert resp.status_code == 200, resp.text
    return {"X-VULNEX-Key": resp.json()["token"]}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "vulnex.db")
    monkeypatch.setattr(config, "ADMIN_EMAIL", ADMIN_EMAIL)
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", ADMIN_PASSWORD_HASH)
    monkeypatch.setattr(config, "ADMIN_PASSWORD", "")
    conn = db.connect()
    db.init_db(conn)
    scan_id = db.start_scan(conn, ["3.0-dev"], "Azure Linux:3")
    db.replace_snapshot(
        conn,
        scan_id,
        packages=[
            _package(),
            # A second spec sharing the same package name must not violate the
            # snapshot's uniqueness constraint (spec_path is the identity).
            _package(
                name="demo",
                spec_path="SPECS/demo/demo-1.1.spec",
                version="1.1.0",
                release="2",
                evr="1.1.0-2",
                patch_count=0,
                is_primary=0,
            ),
        ],
        patches=[_patch()],
        findings=[
            _finding(),
            _finding(
                cve_id="CVE-2024-0001",
                status="patched",
                severity="medium",
                patch_name="CVE-2024-0001.patch",
                patch_status="applied",
                confidence=0.95,
            ),
        ],
    )
    db.finish_scan(
        conn, scan_id, status="success",
        counts={"packages": 1, "findings": 2, "affected": 1, "patched": 1},
    )
    conn.close()
    return TestClient(app)


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_stats(client):
    data = client.get("/api/stats").json()
    assert data["total_packages"] == 2
    assert data["affected"] == 1
    assert data["patched"] == 1
    assert data["severity"]["high"] == 1
    assert data["repository"]["repo"] == config.REPO_NAME


def test_findings_filter_by_status(client):
    data = client.get("/api/findings", params={"status": "affected"}).json()
    assert data["total"] == 1
    assert data["items"][0]["cve_id"] == "CVE-2024-0500"
    # references are rehydrated from the refs column
    assert data["items"][0]["references"][0]["url"] == "https://example.com/fix"


def test_packages_and_detail(client):
    listing = client.get("/api/packages").json()
    assert listing["total"] == 2
    # Name lookup resolves to the primary spec, and its findings/patches are
    # scoped to that spec only.
    detail = client.get("/api/packages/demo").json()
    assert detail["evr"] == "1.2.3-4"
    assert detail["is_primary"] == 1
    assert len(detail["patches"]) == 1
    # Only the open exposure is listed; the patched finding is not served.
    assert len(detail["findings"]) == 1
    # Sibling versioned specs are exposed as variants.
    assert len(detail["variants"]) == 2
    # Explicit spec lookup disambiguates duplicate package names.
    variant = client.get(
        "/api/packages/demo", params={"spec": "SPECS/demo/demo-1.1.spec"}
    ).json()
    assert variant["evr"] == "1.1.0-2"
    assert variant["findings"] == []


def test_fixed_and_ruled_out_cves_are_not_served(client):
    """The console only ever shows open exposures.

    CVE-2024-0001 is ``patched`` in the fixture (a distro backport); it must not
    appear in any list, CVE page, package page or count.
    """
    assert client.get("/api/findings").json()["total"] == 1
    # There is no status filter: a stray ?status= is ignored, never honoured.
    assert client.get("/api/findings", params={"status": "patched"}).json()["total"] == 1
    assert client.get("/api/findings", params={"status": ""}).json()["total"] == 1

    assert client.get("/api/cves/CVE-2024-0001", params={"enrich": "false"}).status_code == 404
    assert client.get("/api/cves/CVE-2024-0001/deep").status_code == 404

    detail = client.get("/api/packages/demo").json()
    assert [f["cve_id"] for f in detail["findings"]] == ["CVE-2024-0500"]

    stats = client.get("/api/stats").json()
    assert stats["total_findings"] == 1
    assert stats["affected"] == 1
    assert stats["patched"] == 1
    assert stats["excluded_findings"] == 1
    assert stats["distinct_cves"] == 1


def test_patch_availability_is_upstream_only_and_unfixed(client):
    """Patch availability describes upstream work on a still-open CVE."""
    finding = client.get("/api/findings").json()["items"][0]
    pa = finding["patch_availability"]
    assert pa["applicable"] is True
    assert pa["source"] == "upstream-fix"
    # The upstream fix commit, never a distro backport blob URL.
    assert pa["patch_link"] == finding["upstream_fix"]
    assert "/blob/" not in pa["patch_link"]
    assert pa["possible_links"] == [finding["upstream_fix"]]
    assert pa["ai_verdict"] == "Patch Available"


def test_cve_detail_and_404(client):
    data = client.get("/api/cves/CVE-2024-0500", params={"enrich": "false"}).json()
    assert data["cve_id"] == "CVE-2024-0500"
    assert len(data["findings"]) == 1
    assert client.get("/api/cves/CVE-9999-0000", params={"enrich": "false"}).status_code == 404


def test_assignment_flow(client, admin):
    created = client.post(
        "/api/assignments",
        headers=admin,
        json={"cve_id": "CVE-2024-0500", "package_name": "demo", "notes": "triage"},
    )
    assert created.status_code == 200
    body = created.json()
    assert body["assignment"]["status"] == "queued"
    assert body["target_repo"] == config.PATCH_TARGET_REPO
    listing = client.get("/api/assignments").json()
    assert len(listing["items"]) == 1


def test_assignment_rejects_unknown_finding(client, admin):
    resp = client.post(
        "/api/assignments",
        headers=admin,
        json={"cve_id": "CVE-1-1", "package_name": "nope"},
    )
    assert resp.status_code == 404


def test_frontend_is_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "VULNEX" in resp.text
