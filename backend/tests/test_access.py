"""Access tiers: read-only by default, admin for triage, automation for the PR.

VULNEX is a shared tool, not a public showcase. A request with no key is always
``viewer``. The admin identity triages, disputes, comments and sets patch
verdicts; the ``automation`` machine identity may do exactly one thing — set the
GitHub CVE PR. These tests pin that boundary on the API rather than trusting the
UI to hide buttons.
"""

import pytest
from fastapi.testclient import TestClient
from test_api import _finding, _package

from vulnex import auth, config, db
from vulnex.api import app

# A human admin signs in with email + password and receives a session token; the
# machine identity keeps a static key. There is no shared "access key" for people.
ADMIN_EMAIL = "lead@example.com"
ADMIN_PASSWORD = "correct horse battery staple"
ADMIN_PASSWORD_HASH = auth.hash_password(ADMIN_PASSWORD)
AUTOMATION_KEY = "test-automation-key"
AUTO = {"X-VULNEX-Key": AUTOMATION_KEY}
KEY_HEADER = "X-VULNEX-Key"
GITHUB_LOGIN = "akhila-dev5"

FINDING = {"cve_id": "CVE-2024-0500", "branch": "3.0-dev",
           "spec_path": "SPECS/demo/demo.spec"}


def _seed(client_db_path):
    conn = db.connect(client_db_path)
    db.init_db(conn)
    scan_id = db.start_scan(conn, ["3.0-dev"], "Azure Linux:3")
    db.replace_snapshot(
        conn, scan_id, packages=[_package()], patches=[], findings=[_finding()]
    )
    db.finish_scan(
        conn, scan_id, status="success",
        counts={"packages": 1, "findings": 1, "affected": 1, "patched": 0},
    )
    conn.close()


@pytest.fixture(autouse=True)
def _clean_sessions():
    """Sessions live on the module-level store, so clear them between tests."""
    auth.sessions.clear()
    yield
    auth.sessions.clear()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A server with password sign-in and the automation key configured."""
    db_path = tmp_path / "vulnex.db"
    monkeypatch.setattr(config, "DB_PATH", db_path)
    monkeypatch.setattr(config, "ADMIN_EMAIL", ADMIN_EMAIL)
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", ADMIN_PASSWORD_HASH)
    monkeypatch.setattr(config, "ADMIN_PASSWORD", "")
    monkeypatch.setattr(config, "AUTOMATION_KEY", AUTOMATION_KEY)
    _seed(db_path)
    return TestClient(app)


@pytest.fixture()
def admin(client):
    """Signed-in admin headers — a real session token from the login endpoint."""
    resp = client.post(
        "/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert resp.status_code == 200, resp.text
    return {"X-VULNEX-Key": resp.json()["token"]}


# -- role resolution --------------------------------------------------------
def test_role_is_read_only_without_a_key(client):
    data = client.get("/api/role").json()
    assert data["role"] == "viewer"
    assert data["write_enabled"] is False
    assert data["can_dispute"] is False and data["can_set_pr"] is False


def test_admin_session_unlocks_triage(client, admin):
    data = client.get("/api/role", headers=admin).json()
    assert data["role"] == "admin"
    assert data["identity"]["identity"] == config.ADMIN_IDENTITY
    assert data["can_dispute"] and data["can_comment"] and data["can_set_pr"]


def test_role_endpoint_advertises_the_sign_in_methods(client):
    data = client.get("/api/role").json()
    assert data["role"] == "viewer"
    assert data["methods"] == {
        "password": True, "github": False, "github_login": GITHUB_LOGIN,
    }


def test_automation_key_can_only_set_the_pr(client):
    data = client.get("/api/role", headers=AUTO).json()
    assert data["role"] == "automation"
    assert data["can_set_pr"] is True
    assert data["can_dispute"] is False
    assert data["can_comment"] is False
    assert data["write_enabled"] is False


# -- sign-in ----------------------------------------------------------------
def test_email_password_login_mints_a_session(client):
    resp = client.post(
        "/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["role"] == "admin" and body["method"] == "password"
    token = body["token"]
    # The token is an opaque session credential, never the password itself.
    assert ADMIN_PASSWORD not in token
    assert client.get("/api/role", headers={KEY_HEADER: token}).json()["role"] == "admin"


def test_login_rejects_a_wrong_password_or_email(client):
    assert client.post(
        "/api/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong"}
    ).status_code == 401
    assert client.post(
        "/api/auth/login",
        json={"email": "someone@else.example", "password": ADMIN_PASSWORD},
    ).status_code == 401
    assert client.get("/api/role").json()["role"] == "viewer"


def test_login_is_unavailable_until_configured(client, monkeypatch):
    monkeypatch.setattr(config, "ADMIN_EMAIL", "")
    monkeypatch.setattr(config, "ADMIN_PASSWORD_HASH", "")
    resp = client.post(
        "/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert resp.status_code == 503


def test_logout_revokes_the_session(client, admin):
    assert client.get("/api/role", headers=admin).json()["role"] == "admin"
    assert client.post("/api/auth/logout", headers=admin).json()["signed_out"] is True
    assert client.get("/api/role", headers=admin).json()["role"] == "viewer"


def test_a_guess_is_not_an_admin_credential(client):
    """The old shared-key credential no longer grants anything."""
    for guess in ("akhila-dev5", "test-admin-key", "admin"):
        assert client.get("/api/role", headers={KEY_HEADER: guess}).json()["role"] == "viewer"


# -- GitHub sign-in ---------------------------------------------------------
def test_github_sign_in_is_unavailable_until_configured(client):
    assert client.get("/api/auth/github", follow_redirects=False).status_code == 503


def test_github_callback_requires_a_fresh_state(client, monkeypatch):
    monkeypatch.setattr(config, "GITHUB_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setattr(config, "GITHUB_OAUTH_CLIENT_SECRET", "secret")
    resp = client.get(
        "/api/auth/github/callback",
        params={"code": "x", "state": "forged"},
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_github_callback_allows_only_the_admin_login(client, monkeypatch):
    monkeypatch.setattr(config, "GITHUB_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setattr(config, "GITHUB_OAUTH_CLIENT_SECRET", "secret")
    monkeypatch.setattr(auth, "github_exchange", lambda code, uri: {"login": "someone-else"})
    start = client.get("/api/auth/github", follow_redirects=False)
    assert start.status_code == 307
    assert "github.com/login/oauth/authorize" in start.headers["location"]
    assert "client_id=cid" in start.headers["location"]
    state = start.headers["location"].split("state=")[1].split("&")[0]
    denied = client.get(
        "/api/auth/github/callback",
        params={"code": "x", "state": state},
        follow_redirects=False,
    )
    assert denied.status_code == 403


def test_github_callback_mints_a_session_for_the_admin(client, monkeypatch):
    monkeypatch.setattr(config, "GITHUB_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setattr(config, "GITHUB_OAUTH_CLIENT_SECRET", "secret")
    monkeypatch.setattr(auth, "github_exchange", lambda code, uri: {"login": GITHUB_LOGIN})
    start = client.get("/api/auth/github", follow_redirects=False)
    state = start.headers["location"].split("state=")[1].split("&")[0]
    done = client.get(
        "/api/auth/github/callback",
        params={"code": "x", "state": state},
        follow_redirects=False,
    )
    assert done.status_code == 307
    location = done.headers["location"]
    assert location.startswith("/#vulnex_token=")
    token = location.split("vulnex_token=")[1]
    assert client.get("/api/role", headers={KEY_HEADER: token}).json()["role"] == "admin"


# -- viewer is read-only ----------------------------------------------------
def test_viewer_cannot_write_anything(client):
    assert client.post(
        "/api/triage/comment", json={**FINDING, "body": "hi"}
    ).status_code == 401
    assert client.post(
        "/api/triage/dispute", json={**FINDING, "reason": "wrong"}
    ).status_code == 401
    assert client.post(
        "/api/triage/github-pr", json={**FINDING, "number": "1"}
    ).status_code == 401
    assert client.post(
        "/api/triage/patch", json={**FINDING, "final_verdict": "No Patch Found"}
    ).status_code == 401
    assert client.post("/api/scan", json={}).status_code == 401
    assert client.post(
        "/api/assignments", json={"cve_id": "CVE-2024-0500", "package_name": "demo"}
    ).status_code == 401


# -- admin triage -----------------------------------------------------------
def test_admin_can_comment_and_dispute(client, admin):
    comment = client.post(
        "/api/triage/comment", headers=admin, json={**FINDING, "body": "Looking into this."}
    )
    assert comment.status_code == 200
    assert comment.json()["comment"]["kind"] == "comment"

    dispute = client.post(
        "/api/triage/dispute",
        headers=admin,
        json={**FINDING, "reason": "The distro backport covers this version."},
    )
    assert dispute.status_code == 200
    assert dispute.json()["comment"]["kind"] == "dispute"
    assert dispute.json()["triage"]["triage_status"] == "disputed"

    # Both entries land in the triage trail, the dispute reason under it.
    row = client.get("/api/triage", params={"status": "affected"}).json()["items"][0]
    bodies = [c["body"] for c in row["comments"]]
    assert bodies == ["Looking into this.", "The distro backport covers this version."]
    assert row["triage"]["triage_status"] == "disputed"


def test_admin_can_override_the_patch_verdict(client, admin):
    resp = client.post(
        "/api/triage/patch",
        headers=admin,
        json={**FINDING, "final_verdict": "Patch Available",
              "patch_link": "https://example.com/fix.diff", "available_since": "2026-09-30"},
    )
    assert resp.status_code == 200
    row = client.get("/api/triage", params={"status": "affected"}).json()["items"][0]
    assert row["triage"]["final_verdict"] == "Patch Available"
    assert row["patch_availability"]["final_verdict"] == "Patch Available"
    assert row["patch_availability"]["overridden"] is True


def test_dispute_and_comment_need_content(client, admin):
    assert client.post(
        "/api/triage/dispute", headers=admin, json={**FINDING, "reason": "  "}
    ).status_code == 400
    assert client.post(
        "/api/triage/comment", headers=admin, json={**FINDING, "body": ""}
    ).status_code == 400
    assert client.post(
        "/api/triage/comment", headers=admin, json={"cve_id": "", "body": "x"}
    ).status_code == 400


# -- automation is narrowly scoped -----------------------------------------
def test_automation_sets_the_pr_but_nothing_else(client):
    resp = client.post(
        "/api/triage/github-pr", headers=AUTO, json={**FINDING, "number": "#19015"}
    )
    assert resp.status_code == 200
    triage = resp.json()["triage"]
    assert triage["github_pr_number"] == "19015"
    assert triage["github_pr_url"].endswith("/pull/19015")
    assert triage["github_pr_set_by"] == config.AUTOMATION_IDENTITY

    # Everything else is refused for the machine identity.
    assert client.post(
        "/api/triage/comment", headers=AUTO, json={**FINDING, "body": "hi"}
    ).status_code == 401
    assert client.post(
        "/api/triage/dispute", headers=AUTO, json={**FINDING, "reason": "x"}
    ).status_code == 401
    assert client.post(
        "/api/triage/patch", headers=AUTO, json={**FINDING, "final_verdict": "Patch Available"}
    ).status_code == 401


def test_pr_number_is_required(client):
    assert client.post(
        "/api/triage/github-pr", headers=AUTO, json={**FINDING, "number": "  "}
    ).status_code == 400


# -- read endpoints expose the derived views --------------------------------
def test_findings_carry_patch_availability_links_and_deep(client):
    finding = client.get("/api/findings", params={"status": "affected"}).json()["items"][0]
    assert finding["links"][0]["label"] == "Ubuntu"
    assert finding["links"][-1]["label"] == "NVD"
    pa = finding["patch_availability"]
    assert pa["ai_verdict"] in ("Patch Available", "No Patch Found")
    assert finding["deep"]["cve_id"] == "CVE-2024-0500"

    deep = client.get(
        "/api/cves/CVE-2024-0500/deep",
        params={"branch": "3.0-dev", "spec": "SPECS/demo/demo.spec"},
    ).json()
    assert deep["affected_files"] == ["src/demo.c"]
    assert deep["tarball"]["name"] == "demo-1.2.3.tar.gz"


def test_stats_expose_roles_without_keys(client):
    roles = client.get("/api/stats").json()["roles"]
    assert roles["admin"]["identity"] == config.ADMIN_IDENTITY
    assert roles["automation"]["email"] == config.AUTOMATION_EMAIL
    assert "capabilities" in roles["automation"]
