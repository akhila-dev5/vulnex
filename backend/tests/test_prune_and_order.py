"""Affected CVEs lead the list; confirmed-patched, already-recorded findings are pruned."""

from __future__ import annotations

from vulnex import db, fixed_cves


def _row(cve, pkg, status, severity="high", **extra):
    base = dict(
        scan_id=1, cve_id=cve, package_name=pkg, package_version="1.0-2", branch="3.0",
        spec_path=f"SPECS/{pkg}/{pkg}.spec", status=status, severity=severity,
        cvss_score=7.0, confidence=0.8, description="d", fixed_version=None, source="t",
    )
    base.update(extra)
    return base


CONFIRMED = dict(status="patched", fix_source="patch", fixed_in_basis="changelog",
                 patch_status="applied", fixed_in="1.0-2")


def _seed(conn, rows):
    for r in rows:
        cols = ",".join(r)
        marks = ",".join("?" * len(r))
        conn.execute(f"INSERT INTO findings ({cols}) VALUES ({marks})", tuple(r.values()))
    conn.commit()


def test_affected_cves_come_before_patched_ones(tmp_path):
    with db.session(tmp_path / "t.db") as conn:
        _seed(conn, [
            _row("CVE-1", "a", **{**CONFIRMED}, severity="critical"),
            _row("CVE-2", "b", "affected", severity="low"),
            _row("CVE-3", "c", "unconfirmed", severity="critical"),
            _row("CVE-4", "d", **{**CONFIRMED}, severity="critical"),
            _row("CVE-4", "e", "affected", severity="critical"),
        ])
        rows, _ = db.list_findings(conn)
        order = [(r["cve_id"], r["status"]) for r in rows]
        # CVE-4 still affects package e, so it leads despite also being patched elsewhere,
        # and its own affected row comes first; patched-only CVE-1 is last.
        assert order[0] == ("CVE-4", "affected") and order[1] == ("CVE-4", "patched")
        assert order[2][0] == "CVE-2" and order[3][0] == "CVE-3" and order[-1][0] == "CVE-1"
        assert all("cve_rank" not in r and "cve_sev" not in r for r in rows)
        detail = db.findings_for_cve(conn, "CVE-4")
        assert [f["status"] for f in detail] == ["affected", "patched"]


def _ledger(*entries):
    return {"packages": [
        {"name": n, "version": v, "fixed": [{"id": c, "fixed_in": "1.0-2", "basis": "changelog"}]}
        for n, v, c in entries
    ]}


def test_prune_deletes_only_confirmed_and_recorded(tmp_path):
    with db.session(tmp_path / "t.db") as conn:
        _seed(conn, [
            _row("CVE-1", "a", **CONFIRMED),                      # confirmed + recorded
            _row("CVE-2", "b", **CONFIRMED),                      # confirmed, NOT recorded
            _row("CVE-3", "c", **{**CONFIRMED, "fixed_in_basis": "spec-evr"}),  # no changelog
            _row("CVE-4", "d", **{**CONFIRMED, "fix_source": "changelog", "patch_status": None}),
            _row("CVE-5", "e", **{**CONFIRMED, "patch_status": "missing-file"}),
            _row("CVE-6", "f", "affected"),
        ])
        recorded = _ledger(("a", "1.0", "CVE-1"), ("c", "1.0", "CVE-3"), ("d", "1.0", "CVE-4"),
                           ("e", "1.0", "CVE-5"), ("f", "1.0", "CVE-6"))
        assert fixed_cves.prune_recorded(conn, recorded, dry_run=True) == 1
        assert conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"] == 6
        assert fixed_cves.prune_recorded(conn, recorded) == 1
        left = {r["cve_id"] for r in conn.execute("SELECT cve_id FROM findings")}
        assert left == {"CVE-2", "CVE-3", "CVE-4", "CVE-5", "CVE-6"}


def test_prune_does_nothing_when_ledger_unreadable(tmp_path):
    with db.session(tmp_path / "t.db") as conn:
        _seed(conn, [_row("CVE-1", "a", **CONFIRMED)])
        assert fixed_cves.prune_recorded(conn, None) == 0
        assert conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"] == 1


def test_merge_keeps_recorded_entries_that_were_pruned():
    old = _ledger(("a", "1.0", "CVE-1"), ("b", "1.0", "CVE-2"))
    new = _ledger(("b", "1.0", "CVE-2"), ("c", "1.0", "CVE-3"))
    merged = fixed_cves.merge_ledgers(old, new)
    ids = sorted(i["id"] for p in merged["packages"] for i in p["fixed"])
    assert ids == ["CVE-1", "CVE-2", "CVE-3"]
    assert merged["stats"]["fixed_cves"] == 3
    assert fixed_cves.merge_ledgers(None, new) is new
