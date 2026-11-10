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
    assert mine["total"] == 1 and mine["groups"][0]["owner"] == DEV
    assert mine["groups"][0]["items"][0]["cve_id"] == FINDING["cve_id"]


def test_workflows_shows_every_developers_packages_with_me_first(client, dev, other):  # noqa: F811
    client.post("/api/triage/claim", json=FINDING, headers=dev)
    # the other developer has claimed nothing but still sees the whole picture
    seen = client.get("/api/workflows", headers=other).json()
    assert seen["total"] == 1 and seen["me"] == OTHER
    assert [g["owner"] for g in seen["groups"]] == [OTHER, DEV]
    assert seen["groups"][0]["total"] == 0
    assert seen["groups"][1]["items"][0]["cve_id"] == FINDING["cve_id"]
    assert seen["groups"][1]["items"][0]["held_via"] == "claimed"


def test_workflows_puts_me_first_then_others_alphabetically(client, dev, other, admin):  # noqa: F811
    client.post("/api/triage/claim", json=FINDING, headers=other)
    seen = client.get("/api/workflows", headers=dev).json()
    assert [g["owner"] for g in seen["groups"]] == [DEV, OTHER]
    # the administrator's email sorts before "dev.*", yet the signed-in account leads
    client.post("/api/triage/release", json=FINDING, headers=other)
    client.post("/api/triage/claim", json=FINDING, headers=admin)
    seen = client.get("/api/workflows", headers=dev).json()
    assert [g["owner"] for g in seen["groups"]] == [DEV, config.ADMIN_EMAIL]


def test_workflows_includes_admin_assigned_packages(client, dev, admin):  # noqa: F811
    made = client.post(
        "/api/assignments",
        headers=admin,
        json={"cve_id": FINDING["cve_id"], "package_name": "demo", "assignee_email": config.ADMIN_EMAIL},
    )
    assert made.status_code == 200
    seen = client.get("/api/workflows", headers=dev).json()
    by_owner = {g["owner"]: g for g in seen["groups"]}
    assert by_owner[config.ADMIN_EMAIL]["items"][0]["held_via"] == "assigned"
    assert by_owner[DEV]["items"] == []


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


ASSIGNEE = "dev1.vulnex@gmail.com"  # an address the administrator can assign to


def _assignee(monkeypatch):
    monkeypatch.setattr(config, "DEVELOPER_EMAILS", config.DEVELOPER_EMAILS | {ASSIGNEE})
    identity = {**config.identity_for("developer"), "identity": ASSIGNEE, "email": ASSIGNEE}
    token, _ = auth.sessions.create(identity, method="google", role="developer")
    return {KEY_HEADER: token}


def _assign(client, admin, email):  # noqa: F811
    made = client.post("/api/assignments", headers=admin, json={
        "cve_id": FINDING["cve_id"], "package_name": "demo", "assignee_email": email})
    assert made.status_code == 200


def test_release_also_takes_back_an_admin_assignment(client, admin, monkeypatch):  # noqa: F811
    me = _assignee(monkeypatch)
    _assign(client, admin, ASSIGNEE)
    held = client.get("/api/workflows", headers=me).json()["groups"][0]
    assert held["owner"] == ASSIGNEE and held["items"][0]["held_via"] == "assigned"
    done = client.post("/api/triage/release", json={**FINDING, "package_name": "demo"}, headers=me)
    assert done.status_code == 200
    assert client.get("/api/workflows", headers=me).json()["total"] == 0


def test_only_the_assignee_or_the_admin_can_release_an_assignment(client, other, admin, monkeypatch):  # noqa: F811
    me = _assignee(monkeypatch)
    _assign(client, admin, ASSIGNEE)
    body = {**FINDING, "package_name": "demo"}
    assert client.post("/api/triage/release", json=body, headers=other).status_code == 409
    assert client.get("/api/workflows", headers=me).json()["total"] == 1
    assert client.post("/api/triage/release", json=body, headers=admin).status_code == 200
    assert client.get("/api/workflows", headers=me).json()["total"] == 0
