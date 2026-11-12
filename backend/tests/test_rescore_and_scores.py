"""Severity from every source, and the administrator's rescore."""

from vulnex.sources.mitre import pick_cvss
from vulnex.sources.nvd import _pick_metric


def test_nvd_uses_a_secondary_score_when_nvd_has_not_analysed_the_cve():
    metrics = {"cvssMetricV31": [{"type": "Secondary", "cvssData": {
        "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 8.4, "baseSeverity": "HIGH"}}]}
    assert _pick_metric(metrics) == ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4, "high")


def test_nvd_prefers_its_own_primary_score_and_falls_back_to_v4():
    both = {"cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"vectorString": "s", "baseScore": 9.8, "baseSeverity": "CRITICAL"}},
        {"type": "Primary", "cvssData": {"vectorString": "p", "baseScore": 7.5, "baseSeverity": "HIGH"}}]}
    assert _pick_metric(both)[1] == 7.5
    v4 = {"cvssMetricV40": [{"type": "Secondary", "cvssData": {"vectorString": "CVSS:4.0/x", "baseScore": 6.9, "baseSeverity": "MEDIUM"}}]}
    assert _pick_metric(v4) == ("CVSS:4.0/x", 6.9, "medium")


def test_mitre_record_score_from_the_cna_or_cisa_adp():
    adp = {"cna": {}, "adp": [{"title": "CISA ADP Vulnrichment", "metrics": [
        {"cvssV3_1": {"baseScore": 8.4, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:L"}}]}]}
    assert pick_cvss(adp) == ("CVSS:3.1/AV:L", 8.4, "high")
    cna = {"cna": {"metrics": [{"cvssV3_1": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "c"}}]}, "adp": adp["adp"]}
    assert pick_cvss(cna)[1] == 5.0
    assert pick_cvss({"cna": {}}) == ("", None, "")


def test_enrichment_limit_serves_cves_without_a_severity_first(monkeypatch):
    from vulnex import scanner
    from vulnex.verification import Finding

    asked = []

    def fake(cve_id, sources=None):
        asked.append(cve_id)
        return {"severity": "high", "cvss_score": 7.5, "cvss_vector": "v", "sources": []}

    monkeypatch.setattr(scanner, "enrich_cve", fake)
    monkeypatch.setattr(scanner, "CVESources", lambda: None)
    known = Finding("CVE-1", "a", "1", "3.0", "SPECS/a/a.spec", "affected", severity="low")
    unknown = Finding("CVE-2", "b", "1", "3.0", "SPECS/b/b.spec", "affected")
    scanner._enrich_findings([known, unknown], scanner.ScanOptions(enrich_limit=1), lambda *a, **k: None)
    assert asked == ["CVE-2"]
    assert (unknown.severity, unknown.cvss_score) == ("high", 7.5)
