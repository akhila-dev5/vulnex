from vulnex.sources.osv import OSVAdvisory, evaluate_events, parse_advisory
from vulnex.spec_parser import parse_spec
from vulnex.verification import (
    STATUS_AFFECTED,
    STATUS_FALSE_POSITIVE,
    STATUS_PATCHED,
    STATUS_UNCONFIRMED,
    build_findings_for_package,
)

SPEC = """Name: demo
Version: 1.2.3
Release: 4%{?dist}
Source0: https://example.com/demo-%{version}.tar.gz
Patch0: CVE-2024-0001.patch
Patch1: CVE-2024-0002.nopatch
"""


def _spec():
    return parse_spec(SPEC, branch="3.0-dev", path="SPECS/demo/demo.spec")


def _advisory(cve, affected=True, fixed="1.2.4-1", events=None):
    return OSVAdvisory(
        id="AZL-1",
        ecosystem="Azure Linux:3",
        cve_ids=[cve],
        details=f"{cve} details",
        severity="high",
        cvss_score=8.1,
        affected=affected,
        fixed_version=fixed,
        events=events if events is not None else [{"introduced": "0"}, {"fixed": fixed}],
    )


def test_patch_marks_cve_as_patched():
    findings = build_findings_for_package(_spec(), [])
    by_cve = {f.cve_id: f for f in findings}
    assert by_cve["CVE-2024-0001"].status == STATUS_PATCHED
    assert by_cve["CVE-2024-0001"].patch_name == "CVE-2024-0001.patch"
    assert by_cve["CVE-2024-0001"].confidence >= 0.9


def test_nopatch_marks_cve_as_false_positive():
    findings = build_findings_for_package(_spec(), [])
    by_cve = {f.cve_id: f for f in findings}
    assert by_cve["CVE-2024-0002"].status == STATUS_FALSE_POSITIVE


def test_patch_overrides_osv_affected():
    findings = build_findings_for_package(_spec(), [_advisory("CVE-2024-0001")])
    by_cve = {f.cve_id: f for f in findings}
    # A backport exists, so even though OSV flags the version it is not affected.
    assert by_cve["CVE-2024-0001"].status == STATUS_PATCHED
    assert by_cve["CVE-2024-0001"].advisory_id == "AZL-1"


def test_affected_when_no_patch_and_range_matches():
    findings = build_findings_for_package(_spec(), [_advisory("CVE-2024-0500")])
    by_cve = {f.cve_id: f for f in findings}
    f = by_cve["CVE-2024-0500"]
    assert f.status == STATUS_AFFECTED
    assert f.fixed_version == "1.2.4-1"
    assert f.severity == "high"
    assert any("RPM version match" in e for e in f.evidence)


def test_affected_unfixed_when_no_fixed_version():
    adv = _advisory(
        "CVE-2024-0600",
        affected=True,
        fixed=None,
        events=[{"introduced": "0"}, {"last_affected": "1.2.3-4"}],
    )
    findings = build_findings_for_package(_spec(), [adv])
    f = {x.cve_id: x for x in findings}["CVE-2024-0600"]
    assert f.status == STATUS_AFFECTED
    assert f.fixed_version is None


def test_unconfirmed_when_no_events():
    adv = _advisory("CVE-2024-0700", affected=False, fixed=None, events=[])
    findings = build_findings_for_package(_spec(), [adv])
    f = {x.cve_id: x for x in findings}["CVE-2024-0700"]
    assert f.status == STATUS_UNCONFIRMED


def test_corroboration_raises_confidence():
    adv = _advisory("CVE-2024-0500")
    base = build_findings_for_package(_spec(), [adv])
    corr = build_findings_for_package(
        _spec(), [adv], {"CVE-2024-0500": ["Red Hat", "Debian"]}
    )
    b = {x.cve_id: x for x in base}["CVE-2024-0500"]
    c = {x.cve_id: x for x in corr}["CVE-2024-0500"]
    assert c.confidence > b.confidence
    assert c.corroborating_sources == ["Red Hat", "Debian"]


def test_evaluate_events_azure_linux_semantics():
    events = [{"introduced": "0"}, {"last_affected": "1.2.3-4"}]
    affected, fixed, introduced = evaluate_events(events, "1.2.3-4")
    assert affected is True and fixed is None
    affected, fixed, _ = evaluate_events(events, "1.2.4-1")
    assert affected is False

    fixed_events = [{"introduced": "0"}, {"fixed": "1.3.1-1"}]
    assert evaluate_events(fixed_events, "1.2.13-1")[0] is True
    affected, fixed, _ = evaluate_events(fixed_events, "1.3.1-1")
    assert affected is False


def test_parse_advisory_maps_upstream_to_cve():
    raw = {
        "id": "AZL-35400",
        "upstream": ["CVE-2023-45853"],
        "summary": "CVE-2023-45853 affecting package zlib",
        "details": "details",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"name": "zlib", "ecosystem": "Azure Linux:3"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.3.1-1"}]}],
            }
        ],
    }
    adv = parse_advisory(raw, "Azure Linux:3", "1.2.13-1")
    assert adv.cve_ids == ["CVE-2023-45853"]
    assert adv.affected is True
    assert adv.fixed_version == "1.3.1-1"
    assert adv.cvss_score == 9.8
    assert adv.severity == "critical"
