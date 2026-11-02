"""Listing findings must not cost one database query per finding.

Against a remote database (Supabase) every query is a network round trip, so a
filtered list over a few thousand findings used to run for minutes and time out.
"""

import pytest
from fastapi.testclient import TestClient

from vulnex import config, db
from vulnex.api import app

COLUMNS = (
    "package_version spec_path severity cvss_score cvss_vector confidence description fixed_version "
    "advisory_id source refs upstream_fix patch_name patch_status fixed_in fixed_in_basis fix_source "
    "affected_files corroborating_sources evidence raw_sources"
).split()
N = 40


def _row(scan, i):
    row = dict.fromkeys(COLUMNS)
    row.update(
        scan_id=scan, cve_id=f"CVE-2024-{1000 + i}", package_name=f"pkg{i}", branch="3.0",
        spec_path=f"SPECS/pkg{i}/pkg{i}.spec", status="affected", severity="high",
    )
    return row


@pytest.fixture()
def client(tmp_path, monkeypatch):
    if not config.DATABASE_URL:
        monkeypatch.setattr(config, "DB_PATH", tmp_path / "q.db")
    conn = db.connect()
    db.init_db(conn)
    scan = db.start_scan(conn, ["3.0"], "Azure Linux:3")
    db.replace_snapshot(conn, scan, [], [], [_row(scan, i) for i in range(N)], branches=["3.0"])
    db.finish_scan(conn, scan, status="success", counts={"packages": N, "findings": N, "affected": N})
    db.upsert_triage(conn, "CVE-2024-1003", "3.0", "SPECS/pkg3/pkg3.spec", package_name="pkg3",
                     owner="dev@example.org", triage_status="disputed")
    conn.close()
    return TestClient(app)


def test_filtered_listing_never_looks_up_triage_one_finding_at_a_time(client, monkeypatch):
    def forbidden(*_a, **_k):
        raise AssertionError("per-finding triage lookup (N+1)")

    monkeypatch.setattr(db, "get_triage", forbidden)
    for params in ({}, {"resolution_status": "affected"}, {"triage_status": "open"}):
        resp = client.get("/api/findings", params={"branch": "3.0", "limit": 100, **params})
        assert resp.status_code == 200, params


def test_triage_is_still_attached_to_the_right_finding(client):
    items = client.get("/api/findings", params={"branch": "3.0", "limit": 100}).json()["items"]
    by_cve = {f["cve_id"]: f for f in items}
    assert len(items) == N
    assert by_cve["CVE-2024-1003"]["triage"]["owner"] == "dev@example.org"
    assert all(f["triage"] is None for cve, f in by_cve.items() if cve != "CVE-2024-1003")


def test_triage_filter_returns_only_the_matching_finding(client):
    resp = client.get("/api/findings", params={"branch": "3.0", "triage_status": "disputed"}).json()
    assert [f["cve_id"] for f in resp["items"]] == ["CVE-2024-1003"] and resp["total"] == 1
