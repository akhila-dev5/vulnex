import base64
import json

import pytest

from vulnex import db, fixed_cves
from vulnex.sources.osv import OSVAdvisory
from vulnex.spec_parser import parse_changelog, parse_spec
from vulnex.triage import patch_availability
from vulnex.verification import build_findings_for_package

SPEC = """Name: demo
Version: 1.2.3
Release: 4%{?dist}
Source0: https://example.com/demo-%{version}.tar.gz
Patch0: CVE-2024-0001.patch
%changelog
* Tue Oct 21 2025 A B <a@b.c> - 1.2.3-4
- Revert CVE-2024-0009 patch
- Fix CVE-2024-0003 by bumping the vendored lib
* Mon Jan 06 2025 A B <a@b.c> - 1:1.2.3-2
- Patch CVE-2024-0001
* Mon Jan 01 2024 A B <a@b.c> - 1.2.3-1
- Original import
"""


def _spec():
    return parse_spec(SPEC, branch="3.0", path="SPECS/demo/demo.spec")


def _finding(spec, cve):
    return {f.cve_id: f for f in build_findings_for_package(spec, [_adv(cve)])}[cve]


def _adv(cve):
    return OSVAdvisory(id="AZL-1", ecosystem="Azure Linux:3", cve_ids=[cve], details="d",
                       severity="high", cvss_score=8.0, affected=True, fixed_version="9.9-1",
                       events=[{"introduced": "0"}, {"fixed": "9.9-1"}])


def test_changelog_entries_and_fixes():
    spec = _spec()
    assert [e.evr for e in spec.changelog] == ["1.2.3-4", "1.2.3-2", "1.2.3-1"]  # epoch dropped
    fixes = spec.changelog_fixes()
    assert fixes["CVE-2024-0001"].evr == "1.2.3-2"
    assert fixes["CVE-2024-0003"].evr == "1.2.3-4"
    assert "CVE-2024-0009" not in fixes  # a revert is not a fix


def test_oldest_changelog_mention_is_the_fix_release():
    entries = parse_changelog(
        "* Mon Jan 06 2025 A <a@b.c> - 2.0-3\\n- CVE-1 again\\n".replace("\\n", "\n")
        + "* Mon Jan 01 2024 A <a@b.c> - 2.0-1\n- Fix CVE-2024-1111\n"
    )
    assert [e.evr for e in entries] == ["2.0-3", "2.0-1"]


def test_changelog_ignored_by_field_parsing():
    assert _spec().evr == "1.2.3-4"


def test_patched_cve_gets_fixed_release_from_changelog():
    f = {x.cve_id: x for x in build_findings_for_package(_spec(), [_adv("CVE-2024-0001")])}["CVE-2024-0001"]
    assert (f.status, f.fix_source, f.fixed_in, f.fixed_in_basis) == ("patched", "patch", "1.2.3-2", "changelog")


def test_patch_without_changelog_entry_falls_back_to_spec_evr():
    spec = parse_spec("Name: d\nVersion: 1\nRelease: 5\nPatch0: CVE-2023-9999.patch\n", "3.0", "SPECS/d/d.spec")
    f = build_findings_for_package(spec, [])[0]
    assert (f.fixed_in, f.fixed_in_basis) == ("1-5", "spec-evr")


def test_changelog_only_fix_marks_advisory_cve_patched():
    f = _finding(_spec(), "CVE-2024-0003")
    assert (f.status, f.fix_source, f.fixed_in) == ("patched", "changelog", "1.2.3-4")


def test_unmentioned_and_reverted_cves_stay_affected():
    for cve in ("CVE-2024-0009", "CVE-2024-7777"):
        f = _finding(_spec(), cve)
        assert f.status == "affected" and f.fixed_in is None


def test_patch_availability_ignores_spec_patch_files():
    base = {"status": "affected", "cve_id": "CVE-1", "branch": "3.0", "spec_path": "SPECS/d/d.spec"}
    with_file = patch_availability({**base, "patch_name": "CVE-1.patch"})
    assert with_file["available"] is False and with_file["ai_verdict"] == "No Patch Found"
    upstream = patch_availability({**base, "upstream_fix": "https://github.com/o/r/commit/abc"})
    assert upstream["available"] is True and upstream["ai_verdict"] == "Patch Available"


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(tmp_path / "t.db")
    db.init_db(c)
    return c


def _seed(conn):
    from vulnex.scanner import _finding_row

    scan = db.start_scan(conn, ["3.0"], "Azure Linux:3")
    rows = [_finding_row(f, scan) for f in build_findings_for_package(
        _spec(), [_adv("CVE-2024-0001"), _adv("CVE-2024-0003"), _adv("CVE-2024-7777")])]
    db.replace_snapshot(conn, scan, [], [], rows, branches=["3.0"])


def test_ledger_lists_only_fixed_cves_with_version_release(conn):
    _seed(conn)
    ledger = fixed_cves.build_ledger(conn, "3.0")
    assert ledger["stats"] == {"packages": 1, "fixed_cves": 2, "from_changelog": 2}
    pkg = ledger["packages"][0]
    assert (pkg["name"], pkg["version"], pkg["release"]) == ("demo", "1.2.3", "4")
    got = {f["id"]: f for f in pkg["fixed"]}
    assert got["CVE-2024-0001"]["fixed_in"] == "1.2.3-2" and got["CVE-2024-0001"]["patch"] == "CVE-2024-0001.patch"
    assert got["CVE-2024-0003"]["via"] == "changelog"
    assert "CVE-2024-7777" not in got
    assert fixed_cves.build_ledger(conn, "4.0")["packages"] == []


def test_old_database_is_migrated(conn):
    for column in ("fixed_in", "fixed_in_basis", "fix_source"):
        conn.execute(f"ALTER TABLE findings DROP COLUMN {column}")
    db.init_db(conn)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    assert {"fixed_in", "fixed_in_basis", "fix_source"} <= cols


class _Resp:
    def __init__(self, status=200, data=None):
        self.status_code, self._data = status, data or {}
        self.content = b"x" if data is not None else b""
        self.text = json.dumps(self._data)

    def json(self):
        return self._data


class _Session:
    def __init__(self, existing=None, branch_exists=False):
        self.calls, self.existing, self.branch_exists = [], existing, branch_exists

    def get(self, url, **kw):
        self.calls.append(("GET", url))
        if "/git/ref/" in url:
            return _Resp(200, {"object": {"sha": "base123"}})
        if self.existing is None:
            return _Resp(404, {})
        return _Resp(200, {"sha": "oldsha", "content": base64.b64encode(self.existing.encode()).decode()})

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw.get("json")))
        if url.endswith("/git/refs") and self.branch_exists:
            return _Resp(422, {})
        return _Resp(201, {"html_url": "https://github.com/x/y/pull/1"})

    def put(self, url, **kw):
        self.calls.append(("PUT", url, kw["json"]))
        return _Resp(200, {})


def test_publish_commits_to_a_branch_and_opens_a_pr(conn):
    _seed(conn)
    ledger = fixed_cves.build_ledger(conn)
    s = _Session()
    out = fixed_cves.publish_ledger(ledger, "tok", repo="o/r", session=s)
    put = next(c for c in s.calls if c[0] == "PUT")
    assert put[1].endswith("/o/r/contents/data/fixed-cves.json")
    assert put[2]["branch"] == "vulnex/fixed-cves" and "sha" not in put[2]
    assert json.loads(base64.b64decode(put[2]["content"]))["stats"]["fixed_cves"] == 2
    assert out["pull_request"].endswith("/pull/1")
    assert not any(c[0] == "PUT" and c[2]["branch"] == "main" for c in s.calls)


def test_publish_skips_when_only_the_timestamp_differs(conn):
    _seed(conn)
    ledger = fixed_cves.build_ledger(conn)
    old = fixed_cves.ledger_body({**ledger, "generated_at": "2020-01-01T00:00:00Z"})
    s = _Session(existing=old)
    assert fixed_cves.publish_ledger(ledger, "tok", repo="o/r", session=s)["changed"] is False
    assert not any(c[0] in ("PUT", "POST") for c in s.calls)


def test_publish_reuses_branch_and_requires_token(conn):
    _seed(conn)
    ledger = fixed_cves.build_ledger(conn)
    s = _Session(existing=fixed_cves.ledger_body({**ledger, "stats": {}}), branch_exists=True)
    assert fixed_cves.publish_ledger(ledger, "tok", repo="o/r", session=s)["changed"] is True
    with pytest.raises(fixed_cves.PublishError):
        fixed_cves.publish_ledger(ledger, "")
