from vulnex.spec_parser import expand, extract_cve_ids, parse_spec

CURL_SPEC = """
Name:           curl
Version:        8.11.1
Release:        11%{?dist}
Summary:        An URL retrieval utility and library
License:        curl
URL:            https://curl.haxx.se
Source0:        https://curl.haxx.se/download/%{name}-%{version}.tar.gz
Patch0:         CVE-2025-0665.patch
Patch1:         CVE-2025-0167.patch
# Patch2:       CVE-1999-0001.patch
Patch3:         fix-general-bug.patch

%description
The cURL package.
"""

OPENSSL_SPEC = """
%define sourcever 3.3.7
Name: openssl
Version: %{sourcever}
Release: 6%{?dist}
Source: https://example.com/openssl-%{version}.tar.gz
Patch100: CVE-2026-31791.patch
# Patch101: CVE-2026-99999.patch
"""


def test_extract_cve_ids_dedupes_and_uppercases():
    assert extract_cve_ids("cve-2020-1234 and CVE-2020-1234 x CVE-2021-1000") == [
        "CVE-2020-1234",
        "CVE-2021-1000",
    ]


def test_expand_handles_optional_and_negated_macros():
    macros = {"name": "curl", "version": "8.11.1"}
    assert expand("%{name}-%{version}.tar.gz", macros) == "curl-8.11.1.tar.gz"
    assert expand("11%{?dist}", macros) == "11"
    assert expand("%{!?foo:fallback}", macros) == "fallback"
    assert expand("%{?foo:value}", macros) == ""


def test_parse_curl_spec_extracts_identity_sources_and_patches():
    spec = parse_spec(CURL_SPEC, branch="3.0-dev", path="SPECS/curl/curl.spec")
    assert spec.name == "curl"
    assert spec.version == "8.11.1"
    assert spec.release == "11"
    assert spec.evr == "8.11.1-11"
    assert spec.primary_source.filename == "curl-8.11.1.tar.gz"
    assert spec.primary_source.is_tarball
    assert spec.primary_source.blob_url.endswith("/curl-8.11.1.tar.gz")

    patch_cves = spec.patch_cves()
    assert "CVE-2025-0665" in patch_cves
    assert "CVE-2025-0167" in patch_cves
    # Commented-out patch must NOT be treated as applied.
    assert "CVE-1999-0001" not in patch_cves
    # Non-CVE patch is retained but carries no CVE ids.
    assert any(p.filename == "fix-general-bug.patch" for p in spec.patches)


def test_parse_openssl_defines_and_commented_patch():
    spec = parse_spec(OPENSSL_SPEC, branch="3.0-dev", path="SPECS/openssl/openssl.spec")
    assert spec.version == "3.3.7"
    assert spec.release == "6"
    assert spec.evr == "3.3.7-6"
    assert "CVE-2026-31791" in spec.patch_cves()
    assert "CVE-2026-99999" not in spec.patch_cves()


def test_nopatch_marker_detection():
    spec_text = """
Name: sqlite
Version: 3.44.0
Release: 4%{?dist}
Patch0: CVE-2015-3717.nopatch
Patch1: CVE-2025-6965.patch
"""
    spec = parse_spec(spec_text, branch="3.0-dev", path="SPECS/sqlite/sqlite.spec")
    nopatch = spec.nopatch_cves()
    assert "CVE-2015-3717" in nopatch
    assert nopatch["CVE-2015-3717"].is_nopatch
    assert nopatch["CVE-2015-3717"].status == "not-affected"
    assert "CVE-2025-6965" in spec.patch_cves()


def test_patch_file_presence_detection():
    spec_text = "Name: demo\nVersion: 1\nRelease: 1\nPatch0: CVE-2024-1.patch\n"
    present = {"SPECS/demo/CVE-2024-1.patch"}
    spec = parse_spec(
        spec_text,
        branch="3.0-dev",
        path="SPECS/demo/demo.spec",
        present_files=present,
    )
    assert spec.patches[0].file_present is True
