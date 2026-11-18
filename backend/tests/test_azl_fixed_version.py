"""The 'Fixed version' shown to users is the azurelinux-test release that patched the CVE.

It must never be the upstream project's fixed version (``fixed_version``), which
only appears in the Deep inspection. (The endpoint-level checks of this now live in the
.NET golden tests: api/Vulnex.Api.Tests.)
"""

from vulnex.triage import azl_fixed_version, decorate_finding


def test_helper_ignores_unpatched_findings():
    assert azl_fixed_version({"status": "affected", "fixed_in": "1-1"}) == (None, None)
    assert azl_fixed_version({"status": "patched", "fixed_in": "1-1", "fixed_in_basis": "changelog"}) == ("1-1", "changelog")
    assert azl_fixed_version({"status": "patched"}) == (None, None)
    row = decorate_finding({"cve_id": "C", "status": "affected", "fixed_version": "5"}, include_links=False)
    assert row["azl_fixed_version"] is None and row["fixed_version"] == "5"
