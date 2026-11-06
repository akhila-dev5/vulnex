"""Each finding remembers when it was first scanned, and new affected CVEs lead the list."""

import pytest
from fastapi.testclient import TestClient

from vulnex import config, db
from vulnex.api import app

COLUMNS = (
    "package_version spec_path severity cvss_score cvss_vector confidence description fixed_version "
    "advisory_id source refs upstream_fix patch_name patch_status fixed_in fixed_in_basis fix_source "
    "affected_files corroborating_sources evidence raw_sources"
).split()


def _row(scan, cve, *, severity="high", status="affected", package="pkg", first_seen=None):
    row = dict.fromkeys(COLUMNS)
    row.update(
        scan_id=scan, cve_id=cve, package_name=package, branch="3.0",
        spec_path=f"SPECS/{package}/{package}.spec", status=status, severity=severity,
    )
    if first_seen:
        row["first_seen"] = first_seen
    return row


def _scan(conn, started_at, rows_for):
    scan = db.start_scan(conn, ["3.0"], "Azure Linux:3")
    conn.execute("UPDATE scans SET started_at = ? WHERE id = ?", (started_at, scan))
    db.replace_snapshot(conn, scan, [], [], rows_for(scan), branches=["3.0"])
    db.finish_scan(conn, scan, status="success")
    return scan


@pytest.fixture()
def conn(tmp_path, monkeypatch):
    if not config.DATABASE_URL:
        monkeypatch.setattr(config, "DB_PATH", tmp_path / "f.db")
    c = db.connect()
    db.init_db(c)
    yield c
    c.close()


def _seen(conn):
    return {r["cve_id"]: r["first_seen"] for r in conn.execute("SELECT cve_id, first_seen FROM findings").fetchall()}


def test_new_findings_start_at_the_scan_time_and_old_ones_keep_their_date(conn):
    _scan(conn, "2026-11-02T06:00:00Z", lambda s: [_row(s, "CVE-2024-0001", package="a")])
    _scan(
        conn,
        "2026-11-05T06:00:00Z",
        lambda s: [_row(s, "CVE-2024-0001", package="a"), _row(s, "CVE-2024-0002", package="b")],
    )
    seen = _seen(conn)
    assert seen["CVE-2024-0001"] == "2026-11-02T06:00:00Z"  # still the first scan
    assert seen["CVE-2024-0002"] == "2026-11-05T06:00:00Z"  # new in the second scan


def test_a_finding_that_leaves_and_returns_is_new_again(conn):
    _scan(conn, "2026-11-02T06:00:00Z", lambda s: [_row(s, "CVE-2024-0001")])
    _scan(conn, "2026-11-03T06:00:00Z", lambda s: [])
    _scan(conn, "2026-11-04T06:00:00Z", lambda s: [_row(s, "CVE-2024-0001")])
    assert _seen(conn)["CVE-2024-0001"] == "2026-11-04T06:00:00Z"


def test_an_explicit_date_wins(conn):
    _scan(conn, "2026-11-05T06:00:00Z", lambda s: [_row(s, "CVE-2024-0001", first_seen="2026-10-01T00:00:00Z")])
    assert _seen(conn)["CVE-2024-0001"] == "2026-10-01T00:00:00Z"


def test_newest_affected_cves_lead_then_severity_then_the_rest(conn):
    _scan(
        conn,
        "2026-11-02T06:00:00Z",
        lambda s: [
            _row(s, "CVE-2024-0001", severity="critical", package="old"),
            _row(s, "CVE-2024-0002", severity="critical", status="patched", package="fixed"),
        ],
    )
    _scan(
        conn,
        "2026-11-05T06:00:00Z",
        lambda s: [
            _row(s, "CVE-2024-0001", severity="critical", package="old"),
            _row(s, "CVE-2024-0002", severity="critical", status="patched", package="fixed"),
            _row(s, "CVE-2024-0003", severity="low", package="newlow"),
            _row(s, "CVE-2024-0004", severity="high", package="newhigh"),
        ],
    )
    rows, _ = db.list_findings(conn, branch="3.0", limit=50)
    # Both new CVEs (Nov 5) beat the older critical one; high before low inside the same scan;
    # the patched CVE is last no matter how severe.
    assert [r["cve_id"] for r in rows] == ["CVE-2024-0004", "CVE-2024-0003", "CVE-2024-0001", "CVE-2024-0002"]


def test_the_api_returns_the_scanned_date(conn):
    _scan(conn, "2026-11-05T06:00:00Z", lambda s: [_row(s, "CVE-2024-0001")])
    items = TestClient(app).get("/api/findings?limit=5").json()["items"]
    assert items[0]["first_seen"] == "2026-11-05T06:00:00Z"
