"""Fixed-CVE ledger: scanned CVEs the distro has already fixed in a spec.

A CVE is *fixed* when the package's ``.spec`` addresses it -- through an applied
``CVE-*.patch`` or a ``%changelog`` entry -- so the shipped package is no longer
exposed. For each one the ledger records the **version-release** the fix shipped
in, taken from the changelog entry that first names the CVE.

The ledger is published to ``data/fixed-cves.json`` in the VulnerabilityData
repository. That repo regenerates its inventory from NVD every six hours, so the
tag cannot live in the generated files: its scanner reads this ledger and stamps
``status: "fixed"`` / ``fixed_in`` onto each matching CVE every time it runs.

This is deliberately separate from *patch availability*, which asks whether an
**upstream** patch exists for a still-open CVE (see ``triage.patch_availability``)
and never looks at what the spec ships.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from typing import Any

import requests

from . import config, db

__all__ = [
    "build_ledger", "ledger_body", "publish_ledger", "merge_ledgers",
    "fetch_recorded_ledger", "prune_recorded", "PublishError", "LEDGER_PATH",
]

LEDGER_PATH = "data/fixed-cves.json"
SCHEMA_VERSION = 1
_API = "https://api.github.com"


class PublishError(RuntimeError):
    """Raised when the ledger cannot be written to VulnerabilityData."""


def _split_evr(evr: str) -> tuple[str, str]:
    """``'3.13.7-9'`` -> ``('3.13.7', '9')``; no release -> ``(evr, '')``."""
    version, sep, release = (evr or "").rpartition("-")
    return (version, release) if sep else (evr or "", "")


def build_ledger(conn: sqlite3.Connection, branch: str = "3.0") -> dict[str, Any]:
    """Collect every fixed CVE from the latest scan, grouped by package."""
    rows = conn.execute(
        """
        SELECT cve_id, package_name, package_version, branch, spec_path,
               fixed_in, fixed_in_basis, fix_source, patch_name
        FROM findings
        WHERE status = 'patched' AND fix_source IS NOT NULL AND branch = ?
        ORDER BY package_name, spec_path, cve_id
        """,
        (branch,),
    ).fetchall()

    packages: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        version, release = _split_evr(row["package_version"])
        key = (row["package_name"], version)
        pkg = packages.setdefault(
            key,
            {
                "name": row["package_name"],
                "version": version,
                "release": release,
                "spec_path": row["spec_path"],
                "fixed": [],
            },
        )
        if any(item["id"] == row["cve_id"] for item in pkg["fixed"]):
            continue
        entry: dict[str, Any] = {
            "id": row["cve_id"],
            "fixed_in": row["fixed_in"] or row["package_version"],
            "basis": row["fixed_in_basis"] or "spec-evr",
            "via": row["fix_source"],
        }
        if row["patch_name"] and row["fix_source"] == "patch":
            entry["patch"] = row["patch_name"]
        pkg["fixed"].append(entry)

    ordered = sorted(packages.values(), key=lambda p: (p["name"], p["version"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": db.utcnow(),
        "source": {
            "generator": "vulnex",
            "repo": f"{config.REPO_OWNER}/{config.REPO_NAME}",
            "branch": branch,
        },
        "stats": {
            "packages": len(ordered),
            "fixed_cves": sum(len(p["fixed"]) for p in ordered),
            "from_changelog": sum(
                1 for p in ordered for f in p["fixed"] if f["basis"] == "changelog"
            ),
        },
        "packages": ordered,
    }


def merge_ledgers(existing: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, Any]:
    """Union of the recorded ledger and a fresh one; the fresh entry wins per CVE.

    The scan prunes findings once they are recorded, so a ledger rebuilt from the
    database alone would forget them. Merging keeps the record complete.
    """
    if not existing:
        return new
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for source in (existing, new):
        for pkg in source.get("packages", []):
            key = (pkg["name"], pkg.get("version", ""))
            target = merged.setdefault(key, {**pkg, "fixed": []})
            if source is new:
                target.update({k: v for k, v in pkg.items() if k != "fixed"})
            by_id = {item["id"]: item for item in target["fixed"]}
            for item in pkg.get("fixed", []):
                by_id[item["id"]] = item
            target["fixed"] = sorted(by_id.values(), key=lambda item: item["id"])
    ordered = sorted(merged.values(), key=lambda p: (p["name"], p.get("version", "")))
    out = {**new, "packages": ordered}
    out["stats"] = {
        "packages": len(ordered),
        "fixed_cves": sum(len(p["fixed"]) for p in ordered),
        "from_changelog": sum(
            1 for p in ordered for f in p["fixed"] if f.get("basis") == "changelog"
        ),
    }
    return out


def fetch_recorded_ledger(
    repo: str | None = None, base: str | None = None, session: requests.Session | None = None
) -> dict[str, Any] | None:
    """The ledger currently on VulnerabilityData's base branch, or None if unreadable."""
    repo = repo or config.VULNERABILITYDATA_REPO
    base = base or config.VULNERABILITYDATA_BRANCH
    url = f"{config.GITHUB_RAW}/{repo}/{base}/{LEDGER_PATH}"
    try:
        resp = (session or requests).get(url, timeout=config.HTTP_TIMEOUT)
        if resp.status_code != 200:
            return None
        return resp.json()
    except (requests.RequestException, ValueError):
        return None


def prune_recorded(
    conn: sqlite3.Connection, recorded: dict[str, Any] | None, branch: str = "3.0",
    dry_run: bool = False,
) -> int:
    """Delete findings that are confirmed patched AND already recorded in the ledger.

    Confirmed means both the spec's applied ``CVE-*.patch`` file and a ``%changelog``
    entry name the fix. Anything not yet in the recorded ledger is kept, so nothing
    is lost if the ledger could not be read or its pull request is still open.
    """
    if not recorded:
        return 0
    keys = {
        (pkg["name"], pkg.get("version", ""), item["id"])
        for pkg in recorded.get("packages", [])
        for item in pkg.get("fixed", [])
    }
    rows = conn.execute(
        f"SELECT id, cve_id, package_name, package_version FROM findings "
        f"WHERE branch = ? AND {db.CONFIRMED_PATCHED_SQL}",
        (branch,),
    ).fetchall()
    doomed = [
        r["id"] for r in rows
        if (r["package_name"], _split_evr(r["package_version"])[0], r["cve_id"]) in keys
    ]
    if doomed and not dry_run:
        for start in range(0, len(doomed), 500):
            chunk = doomed[start:start + 500]
            marks = ",".join("?" * len(chunk))
            conn.execute(f"DELETE FROM findings WHERE id IN ({marks})", chunk)
        conn.commit()
    return len(doomed)


def ledger_body(ledger: dict[str, Any]) -> str:
    """Stable JSON text for the ledger (sorted keys, trailing newline)."""
    return json.dumps(ledger, indent=2, sort_keys=True) + "\n"


def _comparable(text: str) -> dict[str, Any]:
    """The ledger with run-specific fields removed, for change detection."""
    data = json.loads(text)
    data.pop("generated_at", None)
    return data


def _check(resp: requests.Response, what: str) -> Any:
    if resp.status_code >= 400:
        raise PublishError(f"{what} failed: HTTP {resp.status_code} {resp.text[:200]}")
    return resp.json() if resp.content else {}


def publish_ledger(
    ledger: dict[str, Any],
    token: str,
    repo: str | None = None,
    base: str = "main",
    branch: str = "vulnex/fixed-cves",
    path: str = LEDGER_PATH,
    open_pr: bool = True,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Commit the ledger to VulnerabilityData on ``branch`` and open a PR.

    Nothing is written when the ledger is unchanged apart from its timestamp.
    The base branch is never pushed to directly. ``token`` needs contents and
    pull-request write access on the repo; it is sent only to api.github.com.
    """
    if not token:
        raise PublishError("A GitHub token is required to publish the ledger.")
    repo = repo or config.VULNERABILITYDATA_REPO
    http = session or requests.Session()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    contents = f"{_API}/repos/{repo}/contents/{path}"

    current = http.get(contents, headers=headers, params={"ref": base}, timeout=config.HTTP_TIMEOUT)
    sha = None
    if current.status_code == 200:
        payload = current.json()
        sha = payload.get("sha")
        existing = base64.b64decode(payload.get("content", "")).decode("utf-8")
        # Keep CVEs recorded earlier even if their findings were pruned since.
        ledger = merge_ledgers(json.loads(existing), ledger)
        body = ledger_body(ledger)
        if _comparable(existing) == _comparable(body):
            return {"changed": False, "reason": "ledger already up to date"}
    elif current.status_code != 404:
        raise PublishError(f"reading {path} failed: HTTP {current.status_code}")
    body = ledger_body(ledger)

    ref = _check(
        http.get(f"{_API}/repos/{repo}/git/ref/heads/{base}", headers=headers, timeout=config.HTTP_TIMEOUT),
        f"reading branch {base}",
    )
    base_sha = ref["object"]["sha"]
    created = http.post(
        f"{_API}/repos/{repo}/git/refs",
        headers=headers,
        json={"ref": f"refs/heads/{branch}", "sha": base_sha},
        timeout=config.HTTP_TIMEOUT,
    )
    if created.status_code == 422:  # branch exists from an earlier run: reuse it
        existing_branch = http.get(
            contents, headers=headers, params={"ref": branch}, timeout=config.HTTP_TIMEOUT
        )
        sha = existing_branch.json().get("sha") if existing_branch.status_code == 200 else sha
    else:
        _check(created, f"creating branch {branch}")

    stats = ledger.get("stats", {})
    put: dict[str, Any] = {
        "message": (
            f"Record {stats.get('fixed_cves', 0)} fixed CVEs "
            f"across {stats.get('packages', 0)} packages"
        ),
        "content": base64.b64encode(body.encode("utf-8")).decode("ascii"),
        "branch": branch,
    }
    if sha:
        put["sha"] = sha
    _check(http.put(contents, headers=headers, json=put, timeout=config.HTTP_TIMEOUT), f"writing {path}")

    result: dict[str, Any] = {"changed": True, "branch": branch, "stats": stats}
    if open_pr:
        pr = http.post(
            f"{_API}/repos/{repo}/pulls",
            headers=headers,
            json={
                "title": "Update fixed-CVE ledger from Vulnex",
                "head": branch,
                "base": base,
                "body": (
                    f"Fixed CVEs found in azurelinux-test spec changelogs: "
                    f"{stats.get('fixed_cves', 0)} across {stats.get('packages', 0)} packages "
                    f"({stats.get('from_changelog', 0)} with a changelog-confirmed version-release)."
                ),
            },
            timeout=config.HTTP_TIMEOUT,
        )
        if pr.status_code == 422:  # a PR for this branch is already open
            result["pull_request"] = "already open"
        else:
            result["pull_request"] = _check(pr, "opening pull request").get("html_url")
    return result
