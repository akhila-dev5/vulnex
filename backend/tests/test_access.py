"""Access tiers: a viewer is read-only, an editor can assign and comment.

VULNEX serves one dashboard to two audiences. The public/recruiter link gets a
read-only showcase; queueing work, moving queue status and leaving triage
comments needs the editor key. These tests pin that boundary on the API rather
than trusting the UI to hide the buttons.
"""

import pytest
from fastapi.testclient import TestClient
from test_api import _finding, _package

from vulnex import config, db
from vulnex.api import app

EDITOR_KEY = "test-editor-key"
KEY_HEADER = "X-VULNEX-Key"


def _seed(client_db_path):
    conn = db.connect(client_db_path)
    db.init_db(conn)
    scan_id = db.start_scan(conn, ["3.0-dev"], "Azure Linux:3")
    db.replace_snapshot(
        conn,
        scan_id,
        packages=[_package()],
        patches=[],
        findings=[_finding()],
    )
    db.finish_scan(
        conn,
        scan_id,
        status="success",
        counts={"packages": 1, "findings": 1, "affected": 1, "patched": 0},
    )
    conn.close()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A server that requires the editor key for every write."""
    db_path = tmp_path / "vulnex.db"
    monkeypatch.setattr(config, "DB_PATH", db_path)
    monkeypatch.setattr(config, "EDITOR_KEY", EDITOR_KEY)
    _seed(db_path)
    return TestClient(app)


def test_role_endpoint_reports_viewer_without_key(client):
    data = client.get("/api/role").json()
    assert data == {"role": "viewer", "write_enabled": False, "key_required": True}


def test_role_endpoint_reports_editor_with_key(client):
    data = client.get("/api/role", headers={KEY_HEADER: EDITOR_KEY}).json()
    assert data["role"] == "editor"
    assert data["write_enabled"] is True


def test_viewer_cannot_queue_work(client):
    resp = client.post(
        "/api/assignments", json={"cve_id": "CVE-2024-0500", "package_name": "demo"}
    )
    assert resp.status_code == 401
    assert "editor access" in resp.json()["detail"]
    # The write is refused, not silently dropped: the queue stays empty.
    assert client.get("/api/assignments").json()["items"] == []


def test_viewer_cannot_scan_or_comment(client):
    assert client.post("/api/scan", json={}).status_code == 401
    assert client.patch("/api/assignments/1", params={"status": "done"}).status_code == 401
    assert client.post("/api/assignments/1/comments", json={"body": "hi"}).status_code == 401


def test_editor_can_queue_comment_and_move_status(client):
    created = client.post(
        "/api/assignments",
        headers={KEY_HEADER: EDITOR_KEY},
        json={"cve_id": "CVE-2024-0500", "package_name": "demo", "notes": "triage me"},
    )
    assert created.status_code == 200
    assignment = created.json()["assignment"]
    assert assignment["status"] == "queued"

    comment = client.post(
        f"/api/assignments/{assignment['id']}/comments",
        headers={KEY_HEADER: EDITOR_KEY},
        json={"body": "Backport exists upstream, queued for review."},
    )
    assert comment.status_code == 200
    assert comment.json()["comment"]["body"].startswith("Backport exists")

    # Viewers still *see* the queue and its triage trail; they just cannot add to it.
    listing = client.get("/api/assignments").json()["items"]
    assert len(listing) == 1
    assert [c["body"] for c in listing[0]["comments"]] == [
        "Backport exists upstream, queued for review."
    ]

    moved = client.patch(
        f"/api/assignments/{assignment['id']}",
        params={"status": "in_progress"},
        headers={KEY_HEADER: EDITOR_KEY},
    )
    assert moved.status_code == 200
    assert moved.json()["assignment"]["status"] == "in_progress"


def test_comment_needs_a_body_and_an_existing_assignment(client):
    client.post(
        "/api/assignments",
        headers={KEY_HEADER: EDITOR_KEY},
        json={"cve_id": "CVE-2024-0500", "package_name": "demo"},
    )
    blank = client.post(
        "/api/assignments/1/comments", headers={KEY_HEADER: EDITOR_KEY}, json={"body": "   "}
    )
    assert blank.status_code == 400
    missing = client.post(
        "/api/assignments/999/comments", headers={KEY_HEADER: EDITOR_KEY}, json={"body": "x"}
    )
    assert missing.status_code == 404


def test_writes_stay_open_when_no_editor_key_is_configured(tmp_path, monkeypatch):
    """Local development keeps working without a key (open editor mode)."""
    db_path = tmp_path / "vulnex.db"
    monkeypatch.setattr(config, "DB_PATH", db_path)
    monkeypatch.setattr(config, "EDITOR_KEY", None)
    _seed(db_path)
    local = TestClient(app)
    assert local.get("/api/role").json()["role"] == "editor"
    created = local.post(
        "/api/assignments", json={"cve_id": "CVE-2024-0500", "package_name": "demo"}
    )
    assert created.status_code == 200


def test_stats_carry_project_and_author_metadata(client):
    repo = client.get("/api/stats").json()["repository"]
    assert repo["project_repo"] == config.PROJECT_REPO
    assert repo["project_url"].endswith(config.PROJECT_REPO)
    assert repo["author"]["name"] == config.AUTHOR_NAME
    assert repo["demo_url"] == config.DEMO_URL
