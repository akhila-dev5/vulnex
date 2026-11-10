"""The Automation section: the automation account's patch-available CVEs, by package."""

from test_access import FINDING, KEY_HEADER, client, admin  # noqa: F401  (shared fixtures)
from test_claim_workflows import dev  # noqa: F401

from vulnex import config

AUTO = "vulnexsecurityautomation@gmail.com"
PACKAGE = {"package_name": "demo", "branch": FINDING["branch"], "spec_path": FINDING["spec_path"]}


def _assign_to_automation(client, admin, verdict="Patch Available"):  # noqa: F811
    client.post("/api/assignments", headers=admin, json={
        "cve_id": FINDING["cve_id"], "package_name": "demo", "assignee_email": AUTO})
    if verdict:
        client.post("/api/triage/patch", headers=admin, json={**FINDING, "final_verdict": verdict})


def test_visitors_are_refused(client):  # noqa: F811
    assert client.get("/api/automation").status_code == 401
    assert client.post("/api/automation/requests", json={**PACKAGE, "cve_ids": [FINDING["cve_id"]], "mode": "new_pr"}).status_code == 401


def test_only_the_automation_accounts_patch_available_cves_are_listed(client, admin, dev):  # noqa: F811
    assert client.get("/api/automation", headers=dev).json()["packages"] == []
    _assign_to_automation(client, admin, verdict="No Patch Found")  # assigned, but the verdict says no patch
    body = client.get("/api/automation", headers=dev).json()
    listed = [i["cve_id"] for g in body["packages"] for i in g["items"]]
    assert FINDING["cve_id"] not in listed
    _assign_to_automation(client, admin)
    body = client.get("/api/automation", headers=dev).json()
    assert body["owner"] == AUTO and body["total"] == 1
    group = body["packages"][0]
    assert group["package_name"] == "demo" and group["items"][0]["cve_id"] == FINDING["cve_id"]


def test_someone_elses_package_is_not_listed(client, admin, dev):  # noqa: F811
    client.post("/api/assignments", headers=admin, json={
        "cve_id": FINDING["cve_id"], "package_name": "demo", "assignee_email": "dev1.vulnex@gmail.com"})
    client.post("/api/triage/patch", headers=admin, json={**FINDING, "final_verdict": "Patch Available"})
    assert client.get("/api/automation", headers=dev).json()["packages"] == []


def test_new_pr_request_is_queued(client, admin, dev):  # noqa: F811
    _assign_to_automation(client, admin)
    made = client.post("/api/automation/requests", headers=dev, json={
        **PACKAGE, "cve_ids": [FINDING["cve_id"]], "mode": "new_pr"})
    assert made.status_code == 200
    record = made.json()["request"]
    assert record["status"] == "queued" and record["mode"] == "new_pr" and record["pr_number"] == ""
    assert record["cve_ids"] == [FINDING["cve_id"]]
    shown = client.get("/api/automation", headers=dev).json()["packages"][0]["requests"]
    assert shown[0]["id"] == record["id"]


def test_existing_pr_needs_a_numeric_pr_number(client, admin, dev):  # noqa: F811
    _assign_to_automation(client, admin)
    body = {**PACKAGE, "cve_ids": [FINDING["cve_id"]], "mode": "existing_pr"}
    assert client.post("/api/automation/requests", headers=dev, json=body).status_code == 400
    assert client.post("/api/automation/requests", headers=dev, json={**body, "pr_number": "abc"}).status_code == 400
    ok = client.post("/api/automation/requests", headers=dev, json={**body, "pr_number": "#123"})
    assert ok.status_code == 200 and ok.json()["request"]["pr_number"] == "123"


def test_rejects_empty_unknown_and_bad_mode(client, admin, dev):  # noqa: F811
    _assign_to_automation(client, admin)
    base = {**PACKAGE, "mode": "new_pr"}
    assert client.post("/api/automation/requests", headers=dev, json={**base, "cve_ids": []}).status_code == 400
    assert client.post("/api/automation/requests", headers=dev, json={**base, "cve_ids": ["CVE-1999-0001"]}).status_code == 400
    assert client.post("/api/automation/requests", headers=dev, json={**base, "cve_ids": [FINDING["cve_id"]], "mode": "both"}).status_code == 400
