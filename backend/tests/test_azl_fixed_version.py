"""The 'Fixed version' shown to users is the azurelinux-test release that patched the CVE.

It must never be the upstream project's fixed version (``fixed_version``), which
only appears in the Deep inspection.
"""

import pytest
from fastapi.testclient import TestClient

from vulnex import config, db
from vulnex.api import app
from vulnex.triage import azl_fixed_version, decorate_finding

COLUMNS = (
    "package_version severity cvss_score cvss_vector confidence description advisory_id source refs "
    "upstream_fix patch_name patch_status affected_files corroborating_sources evidence raw_sources"
).split()


def _row(scan, cve, pkg, status, **over):
    row = dict.fromkeys(COLUMNS)
    row.update(
        scan_id=scan, cve_id=cve, package_name=pkg, branch="3.0", spec_path=f"SPECS/{pkg}/{pkg}.spec",
        status=status, severity="high", fixed_version="9.9.9-upstream",
        fixed_in=None, fixed_in_basis=None, fix_source=None,
    )
    row.update(over)
    return row


@pytest.fixture()
def client(tmp_path, monkeypatch):
    if not config.DATABASE_URL:
        monkeypatch.setattr(config, "DB_PATH", tmp_path / "f.db")
    conn = db.connect()
    db.init_db(conn)
    scan = db.start_scan(conn, ["3.0"], "Azure Linux:3")
    rows = [
        _row(scan, "CVE-2025-0001", "open", "affected"),
        _row(scan, "CVE-2025-0002", "done", "patched", fixed_in="1.2-3", fixed_in_basis="changelog", fix_source="patch"),
        _row(scan, "CVE-2025-0003", "bound", "patched", fixed_in="2.0-5", fixed_in_basis="spec-evr", fix_source="patch"),
        # a leftover value on a row that is not patched must not leak through
        _row(scan, "CVE-2025-0004", "odd", "unconfirmed", fixed_in="1.0-1", fixed_in_basis="changelog"),
    ]
    db.replace_snapshot(conn, scan, [], [], rows, branches=["3.0"])
    db.finish_scan(conn, scan, status="success", counts={"packages": 4, "findings": 4})
    conn.close()
    return TestClient(app)


def _items(client, **params):
    return {f["package_name"]: f for f in client.get("/api/findings", params={"branch": "3.0", **params}).json()["items"]}


def test_only_patched_findings_have_an_azl_fixed_version(client):
    items = _items(client)
    assert items["open"]["azl_fixed_version"] is None
    assert items["done"]["azl_fixed_version"] == "1.2-3" and items["done"]["azl_fixed_basis"] == "changelog"
    assert items["bound"]["azl_fixed_basis"] == "spec-evr"
    assert items["odd"]["azl_fixed_version"] is None


def test_upstream_version_is_still_in_the_payload_but_not_as_the_azl_fix(client):
    items = _items(client)
    assert items["open"]["fixed_version"] == "9.9.9-upstream"  # upstream, kept for Deep
    assert all(f["azl_fixed_version"] != "9.9.9-upstream" for f in items.values())


def test_fixed_version_filter_matches_the_azl_release_not_upstream(client):
    assert set(_items(client, fixed_version="1.2-3")) == {"done"}
    assert _items(client, fixed_version="9.9.9") == {}  # the upstream number matches nothing


def test_deep_view_reports_the_upstream_fixed_version(client):
    deep = client.get("/api/cves/CVE-2025-0001/deep", params={"branch": "3.0", "spec": "SPECS/open/open.spec"}).json()
    assert deep["upstream_fixed_version"] == "9.9.9-upstream"


def test_helper_ignores_unpatched_findings():
    assert azl_fixed_version({"status": "affected", "fixed_in": "1-1"}) == (None, None)
    assert azl_fixed_version({"status": "patched", "fixed_in": "1-1", "fixed_in_basis": "changelog"}) == ("1-1", "changelog")
    assert azl_fixed_version({"status": "patched"}) == (None, None)
    row = decorate_finding({"cve_id": "C", "status": "affected", "fixed_version": "5"}, include_links=False)
    assert row["azl_fixed_version"] is None and row["fixed_version"] == "5"
