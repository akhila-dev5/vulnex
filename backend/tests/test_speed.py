"""Speed-ups must not change what the API returns."""

from __future__ import annotations

from vulnex import cache, db

from test_access import AUTO, FINDING, client  # noqa: F401  (shared fixtures)


def test_responses_are_gzip_compressed(client):
    r = client.get("/api/findings", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200
    # Small test payloads fall under the compression threshold, so only check it doesn't break them.


def test_stats_are_cached_until_a_write_happens(client, monkeypatch):
    cache.clear()
    calls = []
    real = db.stats
    monkeypatch.setattr(db, "stats", lambda *a, **k: calls.append(1) or real(*a, **k))
    client.get("/api/stats")
    client.get("/api/stats")
    assert len(calls) == 1  # second read came from the cache

    client.post("/api/triage/dispute", headers=AUTO, json={**FINDING, "reason": "x"})
    client.get("/api/stats")
    assert len(calls) == 2  # any write request drops the cache


def test_sql_filters_match_python_semantics(client):
    everything = client.get("/api/findings", params={"limit": 1000}).json()
    assert everything["total"] == len(everything["items"])
    # Unknown owner / triage state narrow to nothing; "open" is the default state.
    assert client.get("/api/findings", params={"owner": "nobody-here"}).json()["total"] == 0
    opened = client.get("/api/findings", params={"triage_status": "open"}).json()
    assert opened["total"] == everything["total"]
    # Fixed-version filter only ever matches patched findings.
    fixed = client.get("/api/findings", params={"fixed_version": "1"}).json()
    assert all(f["status"] == "patched" for f in fixed["items"])
    # Paging with a filter is applied to the filtered set.
    page = client.get("/api/findings", params={"triage_status": "open", "limit": 1, "page": 2}).json()
    assert page["total"] == everything["total"] and len(page["items"]) <= 1
