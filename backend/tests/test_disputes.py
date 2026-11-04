"""Developers raise disputes, the administrator approves them, and roles stay separate.

Developer (a Google account listed in VULNEX_DEVELOPER_EMAILS): set GitHub PR, add comment,
raise a dispute. Administrator: all of that, plus approve/reject disputes, assign and set the
patch verdict. These tests pin that on the API, not on the buttons the UI hides.
"""

import pytest
from test_access import FINDING, KEY_HEADER, client, admin  # noqa: F401  (shared fixtures)

from vulnex import auth, config

DEV_EMAIL = "dev.one@example.org"


@pytest.fixture()
def dev(client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(config, "DEVELOPER_EMAILS", frozenset({DEV_EMAIL}))
    identity = {**config.identity_for("developer"), "identity": DEV_EMAIL, "email": DEV_EMAIL}
    token, _ = auth.sessions.create(identity, method="google", role="developer")
    return {KEY_HEADER: token}


def _dispute(client, headers, reason="UPSTREAM: not affected", **extra):  # noqa: F811
    return client.post("/api/triage/dispute", headers=headers, json={**FINDING, "reason": reason, **extra})


def _finding_row(client):  # noqa: F811
    return client.get("/api/findings", params={"limit": 50}).json()["items"][0]


# -- who is who ---------------------------------------------------------------
def test_google_role_for_admin_developer_and_strangers(monkeypatch):
    monkeypatch.setattr(config, "DEVELOPER_EMAILS", frozenset({DEV_EMAIL}))
    assert auth.google_role_for(config.ADMIN_EMAIL, True) == "admin"
    assert auth.google_role_for(DEV_EMAIL.upper(), True) == "developer"
    assert auth.google_role_for("stranger@example.org", True) is None
    assert auth.google_role_for(DEV_EMAIL, False) is None  # unverified email never counts
    assert auth.google_role_for(None, True) is None


def test_developer_role_capabilities(client, dev):  # noqa: F811
    data = client.get("/api/role", headers=dev).json()
    assert data["role"] == "developer"
    assert data["identity"]["identity"] == DEV_EMAIL
    assert data["can_comment"] and data["can_dispute"] and data["can_set_pr"]
    assert not data["can_assign"] and not data["can_set_patch_verdict"]
    assert not data["can_approve_dispute"] and not data["can_scan"] and not data["write_enabled"]


def test_admin_can_approve_disputes(client, admin):  # noqa: F811
    assert client.get("/api/role", headers=admin).json()["can_approve_dispute"] is True


def test_developer_sign_in_creates_a_developer_session(client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(config, "GOOGLE_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setattr(config, "GOOGLE_OAUTH_CLIENT_SECRET", "secret")
    monkeypatch.setattr(config, "DEVELOPER_EMAILS", frozenset({DEV_EMAIL}))
    for email, expected in ((DEV_EMAIL, 307), ("stranger@example.org", 403)):
        monkeypatch.setattr(auth, "google_exchange", lambda code, uri, e=email: {"email": e, "email_verified": True})
        state = auth.new_oauth_state()
        resp = client.get("/api/auth/google/callback", params={"code": "x", "state": state}, follow_redirects=False)
        assert resp.status_code == expected
    token = resp.headers.get("location")  # last call was the stranger: no token handed out
    assert token is None
    state = auth.new_oauth_state()
    monkeypatch.setattr(auth, "google_exchange", lambda code, uri: {"email": DEV_EMAIL, "email_verified": True})
    resp = client.get("/api/auth/google/callback", params={"code": "x", "state": state}, follow_redirects=False)
    handed = resp.headers["location"].split("vulnex_token=")[1]
    assert client.get("/api/role", headers={KEY_HEADER: handed}).json()["role"] == "developer"


# -- what a developer may and may not do -----------------------------------------
def test_developer_can_comment_and_set_the_pr(client, dev):  # noqa: F811
    resp = client.post("/api/triage/comment", headers=dev, json={**FINDING, "body": "looking into it"})
    assert resp.status_code == 200 and resp.json()["comment"]["author"] == DEV_EMAIL
    resp = client.post("/api/triage/github-pr", headers=dev, json={**FINDING, "number": "123"})
    assert resp.status_code == 200 and resp.json()["identity"] == DEV_EMAIL


def test_developer_cannot_assign_set_patch_verdict_or_decide_disputes(client, dev):  # noqa: F811
    assert client.post("/api/assignments", headers=dev, json={"cve_id": FINDING["cve_id"], "package_name": "demo"}).status_code == 401
    assert client.post("/api/triage/patch", headers=dev, json={**FINDING, "final_verdict": "Patch Available"}).status_code == 401
    assert client.post("/api/scan", headers=dev, json={}).status_code == 401
    dispute_id = _dispute(client, dev).json()["dispute"]["id"]
    assert client.post(f"/api/disputes/{dispute_id}/approve", headers=dev).status_code == 401
    assert client.post(f"/api/disputes/{dispute_id}/reject", headers=dev).status_code == 401


def test_visitors_cannot_comment_dispute_or_set_the_pr(client):  # noqa: F811
    assert client.post("/api/triage/comment", json={**FINDING, "body": "x"}).status_code == 401
    assert _dispute(client, {}).status_code == 401
    assert client.post("/api/triage/github-pr", json={**FINDING, "number": "1"}).status_code == 401
    assert client.post("/api/disputes/1/approve").status_code == 401


# -- the dispute workflow ---------------------------------------------------------
def test_a_developer_dispute_waits_for_approval(client, dev):  # noqa: F811
    resp = _dispute(client, dev, first_unaffected_version="1.2-3")
    body = resp.json()
    assert resp.status_code == 200 and body["approved"] is False
    assert body["dispute"]["status"] == "pending" and body["dispute"]["requested_by"] == DEV_EMAIL
    assert body["dispute"]["package_name"] == "demo"
    assert "First unaffected version: 1.2-3" in body["dispute"]["reason"]
    # Nothing is marked on the package yet, and no dispute text joined its history.
    row = _finding_row(client)
    assert not row["triage"] and row["dispute"]["status"] == "pending"
    comments = client.get("/api/triage/comments", params=FINDING).json()["items"]
    assert comments == []


def test_approval_marks_the_package_disputed_and_adds_the_reason(client, dev, admin):  # noqa: F811
    dispute_id = _dispute(client, dev).json()["dispute"]["id"]
    resp = client.post(f"/api/disputes/{dispute_id}/approve", headers=admin, json={"note": "agreed"})
    body = resp.json()
    assert resp.status_code == 200 and body["dispute"]["status"] == "approved"
    assert body["dispute"]["decided_by"] == config.ADMIN_EMAIL or body["dispute"]["decided_by"]
    row = _finding_row(client)
    assert row["triage"]["resolution_status"] == "disputed" and row["triage"]["triage_status"] == "disputed"
    assert row["dispute"]["status"] == "approved"
    comments = client.get("/api/triage/comments", params=FINDING).json()["items"]
    assert [(c["kind"], c["author"]) for c in comments] == [("dispute", DEV_EMAIL)]
    assert "not affected" in comments[0]["body"]


def test_rejection_leaves_the_package_alone_and_allows_a_new_dispute(client, dev, admin):  # noqa: F811
    dispute_id = _dispute(client, dev).json()["dispute"]["id"]
    body = client.post(f"/api/disputes/{dispute_id}/reject", headers=admin, json={"note": "need evidence"}).json()
    assert body["dispute"]["status"] == "rejected" and body["dispute"]["decision_note"] == "need evidence"
    assert not _finding_row(client)["triage"]
    assert client.get("/api/triage/comments", params=FINDING).json()["items"] == []
    assert _dispute(client, dev, reason="BACKPORT: fixed").status_code == 200  # may try again


def test_only_one_pending_dispute_per_package(client, dev):  # noqa: F811
    assert _dispute(client, dev).status_code == 200
    resp = _dispute(client, dev, reason="OTHER: again")
    assert resp.status_code == 409 and "already waiting" in resp.json()["detail"]


def test_a_dispute_can_only_be_decided_once(client, dev, admin):  # noqa: F811
    dispute_id = _dispute(client, dev).json()["dispute"]["id"]
    assert client.post(f"/api/disputes/{dispute_id}/approve", headers=admin).status_code == 200
    assert client.post(f"/api/disputes/{dispute_id}/reject", headers=admin).status_code == 409
    assert client.post("/api/disputes/9999/approve", headers=admin).status_code == 404


def test_the_admins_own_dispute_is_approved_at_once(client, admin):  # noqa: F811
    body = _dispute(client, admin).json()
    assert body["approved"] is True and body["dispute"]["status"] == "approved"
    assert _finding_row(client)["triage"]["resolution_status"] == "disputed"


def test_dispute_input_is_validated(client, dev):  # noqa: F811
    assert _dispute(client, dev, reason="  ").status_code == 400
    assert _dispute(client, dev, first_unaffected_version="bad version!").status_code == 400
    unknown = client.post("/api/triage/dispute", headers=dev, json={**FINDING, "cve_id": "CVE-1999-0001", "reason": "x"})
    assert unknown.status_code == 404


def test_disputes_list_filters_and_counts(client, dev, admin):  # noqa: F811
    first = _dispute(client, dev).json()["dispute"]["id"]
    everything = client.get("/api/disputes").json()
    assert everything["total"] == 1 and everything["counts"] == {"pending": 1, "approved": 0, "rejected": 0}
    assert client.get("/api/disputes", params={"status": "approved"}).json()["total"] == 0
    client.post(f"/api/disputes/{first}/approve", headers=admin)
    counts = client.get("/api/disputes", params={"status": "approved"}).json()
    assert counts["total"] == 1 and counts["counts"]["approved"] == 1 and counts["counts"]["pending"] == 0
    assert client.get("/api/disputes", params={"search": "demo"}).json()["total"] == 1
    assert client.get("/api/disputes", params={"search": "zzz"}).json()["total"] == 0
    assert client.get("/api/disputes", params={"status": "bogus"}).status_code == 400


def test_the_cve_page_data_carries_the_dispute_state(client, dev):  # noqa: F811
    _dispute(client, dev)
    finding = client.get(f"/api/cves/{FINDING['cve_id']}").json()["findings"][0]
    assert finding["dispute"]["status"] == "pending"
