"""Claim a package, and the Workflows list that tracks what you claimed."""

import pytest
from test_access import FINDING, KEY_HEADER, client, admin  # noqa: F401  (shared fixtures)

from vulnex import auth, config

DEV = "dev.one@example.org"
OTHER = "dev.two@example.org"


def _sign_in(email, monkeypatch):
    monkeypatch.setattr(config, "DEVELOPER_EMAILS", config.DEVELOPER_EMAILS | {DEV, OTHER})
    identity = {**config.identity_for("developer"), "identity": email, "email": email}
    token, _ = auth.sessions.create(identity, method="google", role="developer")
    return {KEY_HEADER: token}


@pytest.fixture()
def dev(client, monkeypatch):  # noqa: F811
    return _sign_in(DEV, monkeypatch)


@pytest.fixture()
def other(client, monkeypatch):  # noqa: F811
    return _sign_in(OTHER, monkeypatch)


def test_automation_account_is_a_developer_and_not_an_admin():
    email = "vulnexsecurityautomation@gmail.com"
    assert auth.google_role_for(email, True) == "developer"
    assert auth.google_role_for(email.upper(), True) == "developer"
    assert auth.google_role_for(email, False) is None
    assert email != config.ADMIN_EMAIL


def test_visitors_cannot_claim_release_or_open_workflows(client):  # noqa: F811
    assert client.post("/api/triage/claim", json=FINDING).status_code == 401
    assert client.post("/api/triage/release", json=FINDING).status_code == 401
    assert client.get("/api/workflows").status_code == 401
    assert client.get("/api/role").json()["can_claim"] is False


def test_a_developer_claims_a_package_and_sees_it_in_workflows(client, dev):  # noqa: F811
    assert client.get("/api/role", headers=dev).json()["can_claim"] is True
    assert client.post("/api/triage/claim", json=FINDING, headers=dev).status_code == 200
    row = client.get("/api/findings").json()["items"][0]
    assert row["triage"]["owner"] == DEV
    mine = client.get("/api/workflows", headers=dev).json()
    assert mine["total"] == 1 and mine["items"][0]["cve_id"] == FINDING["cve_id"]


def test_workflows_only_lists_my_own_claims(client, dev, other):  # noqa: F811
    client.post("/api/triage/claim", json=FINDING, headers=dev)
    assert client.get("/api/workflows", headers=other).json()["total"] == 0


def test_a_claimed_package_cannot_be_taken_by_another_developer(client, dev, other, admin):  # noqa: F811
    client.post("/api/triage/claim", json=FINDING, headers=dev)
    taken = client.post("/api/triage/claim", json=FINDING, headers=other)
    assert taken.status_code == 409 and DEV in taken.json()["detail"]
    assert client.post("/api/triage/release", json=FINDING, headers=other).status_code == 409
    # claiming again as the owner is harmless, and the administrator may take over
    assert client.post("/api/triage/claim", json=FINDING, headers=dev).status_code == 200
    assert client.post("/api/triage/claim", json=FINDING, headers=admin).status_code == 200
    assert client.get("/api/findings").json()["items"][0]["triage"]["owner"] == config.ADMIN_EMAIL


def test_release_clears_the_owner(client, dev):  # noqa: F811
    client.post("/api/triage/claim", json=FINDING, headers=dev)
    assert client.post("/api/triage/release", json=FINDING, headers=dev).status_code == 200
    assert client.get("/api/workflows", headers=dev).json()["total"] == 0
    assert client.get("/api/findings").json()["items"][0]["triage"]["owner"] == ""
