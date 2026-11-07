"""Severity from every source, and the administrator's rescore."""

import pytest
from test_access import FINDING, KEY_HEADER, client, admin  # noqa: F401  (shared fixtures)

from vulnex import auth, config
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


DEV_EMAIL = "dev.one@example.org"
URL = "/api/cves/CVE-2024-0500/rescore"
BODY = {"severity": "critical", "cvss_score": 9.1, "reason": "Reachable from the network in our build"}


@pytest.fixture()
def dev(client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(config, "DEVELOPER_EMAILS", frozenset({DEV_EMAIL}))
    identity = {**config.identity_for("developer"), "identity": DEV_EMAIL, "email": DEV_EMAIL}
    token, _ = auth.sessions.create(identity, method="google", role="developer")
    return {KEY_HEADER: token}


def test_only_the_admin_can_rescore(client, admin, dev):  # noqa: F811
    assert client.post(URL, json=BODY).status_code == 401
    assert client.post(URL, json=BODY, headers=dev).status_code == 401
    assert client.get("/api/role", headers=dev).json()["can_rescore"] is False
    assert client.get("/api/role", headers=admin).json()["can_rescore"] is True


def test_rescore_validates_its_input(client, admin):  # noqa: F811
    assert client.post(URL, json={**BODY, "reason": "  "}, headers=admin).status_code == 400
    assert client.post(URL, json={**BODY, "severity": "scary"}, headers=admin).status_code == 400
    assert client.post(URL, json={**BODY, "cvss_score": 11}, headers=admin).status_code == 400
    assert client.post("/api/cves/CVE-1999-0001/rescore", json=BODY, headers=admin).status_code == 404


def test_rescore_changes_severity_and_score_everywhere(client, admin):  # noqa: F811
    before = client.get("/api/findings").json()["items"][0]
    assert before["severity"] == "high" and "rescore" not in before
    assert client.post(URL, json=BODY, headers=admin).status_code == 200

    row = client.get("/api/findings").json()["items"][0]
    assert (row["severity"], row["cvss_score"]) == ("critical", 9.1)
    assert row["scanned_severity"] == "high" and row["scanned_cvss_score"] == 8.1
    assert row["rescore"]["reason"] == BODY["reason"]

    detail = client.get("/api/cves/CVE-2024-0500", params={"enrich": "false"}).json()
    assert detail["findings"][0]["severity"] == "critical"
    # filters and the summary cards use the new severity too
    assert client.get("/api/findings", params={"severity": "critical"}).json()["total"] == 1
    assert client.get("/api/findings", params={"severity": "high"}).json()["total"] == 0
    assert client.get("/api/stats").json()["severity"]["critical"] == 1


def test_rescoring_again_keeps_the_first_scanned_values(client, admin):  # noqa: F811
    client.post(URL, json=BODY, headers=admin)
    client.post(URL, json={"severity": "low", "cvss_score": 3.1, "reason": "Fixed in config"}, headers=admin)
    from vulnex import db
    with db.session(None if config.DATABASE_URL else config.DB_PATH) as conn:
        row = db.get_rescore(conn, "CVE-2024-0500")
    assert (row["severity"], row["original_severity"], row["original_cvss_score"]) == ("low", "high", 8.1)


def test_a_new_scan_does_not_undo_a_rescore(client, admin):  # noqa: F811
    client.post(URL, json=BODY, headers=admin)
    from test_api import _finding
    from vulnex import db
    with db.session(None if config.DATABASE_URL else config.DB_PATH) as conn:
        scan_id = db.start_scan(conn, ["3.0-dev"], "Azure Linux:3")
        db.replace_snapshot(conn, scan_id, packages=[], patches=[], findings=[_finding(scan_id=scan_id, severity="medium")])
    assert client.get("/api/findings").json()["items"][0]["severity"] == "critical"


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
