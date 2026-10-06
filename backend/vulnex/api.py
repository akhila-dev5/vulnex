"""VULNEX FastAPI application.

Serves the JSON API consumed by the dashboard and (when present) the built
static frontend. A single-process background thread runs scans so "Scan Now"
works without any external queue or paid infrastructure.
"""

from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, config, db
from .enrichment import enrich_cve
from .scanner import ScanOptions, run_scan

@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Make sure the snapshot DB carries the current schema before serving."""
    conn = db.connect()
    try:
        db.init_db(conn)
    finally:
        conn.close()
    yield


app = FastAPI(
    title="VULNEX API",
    version=__version__,
    description="Azure Linux CVE scanner and security dashboard API.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# -- scan manager -----------------------------------------------------------
class ScanManager:
    """Runs at most one scan at a time in a background thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.state: dict[str, Any] = {
            "running": False,
            "stage": "idle",
            "started_at": None,
            "finished_at": None,
            "log": [],
            "result": None,
            "error": None,
        }

    def _log(self, message: str) -> None:
        with self._lock:
            entry = {"at": _now(), "message": message}
            self.state["stage"] = message
            self.state["log"] = (self.state["log"] + [entry])[-60:]
            self.state["started_at"] = self.state["started_at"] or _now()

    def start(self, options: ScanOptions) -> bool:
        with self._lock:
            if self.state["running"]:
                return False
            self.state.update(
                {
                    "running": True,
                    "stage": "starting",
                    "started_at": _now(),
                    "finished_at": None,
                    "log": [],
                    "result": None,
                    "error": None,
                }
            )
        self._thread = threading.Thread(target=self._run, args=(options,), daemon=True)
        self._thread.start()
        return True

    def _run(self, options: ScanOptions) -> None:
        conn = db.connect()
        db.init_db(conn)
        try:
            def progress(message: str, **extra: Any) -> None:
                self._log(message)

            result = run_scan(conn, options, progress=progress)
            with self._lock:
                self.state["result"] = result
                self.state["stage"] = "complete"
        except Exception as exc:  # pragma: no cover
            with self._lock:
                self.state["error"] = str(exc)
                self.state["stage"] = "failed"
        finally:
            conn.close()
            with self._lock:
                self.state["running"] = False
                self.state["finished_at"] = _now()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self.state)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


manager = ScanManager()


# -- access tiers -----------------------------------------------------------
# Two roles share one dashboard. ``viewer`` is the read-only showcase used for
# public/recruiter links; ``editor`` can queue work and leave triage comments.
# Writes require the ``X-VULNEX-Key`` header once ``VULNEX_EDITOR_KEY`` is set; a
# server without that key is in local "open editor" mode.
ROLE_VIEWER = "viewer"
ROLE_EDITOR = "editor"


def _presented_key(request: Request) -> str | None:
    return request.headers.get("x-vulnex-key") or None


def resolve_role(request: Request) -> str:
    if not config.editor_key_required():
        return ROLE_EDITOR
    key = _presented_key(request)
    return ROLE_EDITOR if key and key == config.EDITOR_KEY else ROLE_VIEWER


def require_editor(request: Request) -> None:
    """Raise 401 for viewers so a write can never slip through the UI gate."""
    if resolve_role(request) != ROLE_EDITOR:
        raise HTTPException(
            status_code=401,
            detail="Read-only view: this action needs editor access. "
                   "Send an X-VULNEX-Key header with the editor key.",
        )


# -- request models ---------------------------------------------------------
class ScanRequest(BaseModel):
    branches: list[str] | None = None
    packages: list[str] | None = None
    limit: int = 0
    enrich: bool = True
    verify_blobs: bool = True


class AssignmentRequest(BaseModel):
    cve_id: str
    package_name: str
    spec_path: str | None = None
    notes: str = ""
    target_repo: str | None = None


class CommentRequest(BaseModel):
    body: str
    author: str = "editor"


# -- read endpoints ---------------------------------------------------------
@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "time": _now()}


@app.get("/api/role")
def get_role(request: Request) -> dict:
    """Which tier the caller is in, so the UI can hide editor-only actions."""
    role = resolve_role(request)
    return {
        "role": role,
        "write_enabled": role == ROLE_EDITOR,
        "key_required": config.editor_key_required(),
    }


@app.get("/api/stats")
def get_stats() -> dict:
    with db.session() as conn:
        data = db.stats(conn)
    data["repository"] = config.repository_metadata()
    return data


@app.get("/api/packages")
def get_packages(
    search: str = "",
    branch: str = "",
    page: int = 1,
    limit: int = Query(50, ge=1, le=500),
) -> dict:
    with db.session() as conn:
        rows, total = db.list_packages(
            conn, search=search, branch=branch, limit=limit, offset=(page - 1) * limit
        )
    return {"items": rows, "total": total, "page": page, "limit": limit}


@app.get("/api/packages/{name}")
def get_package(name: str, branch: str | None = None, spec: str | None = None) -> dict:
    with db.session() as conn:
        pkg = db.get_package(conn, name, branch, spec_path=spec)
    if not pkg:
        raise HTTPException(status_code=404, detail="Package not found")
    return pkg


@app.get("/api/findings")
def get_findings(
    status: str = "",
    severity: str = "",
    search: str = "",
    package: str = "",
    branch: str = "",
    page: int = 1,
    limit: int = Query(100, ge=1, le=1000),
) -> dict:
    with db.session() as conn:
        rows, total = db.list_findings(
            conn,
            status=status,
            severity=severity,
            search=search,
            package=package,
            branch=branch,
            limit=limit,
            offset=(page - 1) * limit,
        )
    return {"items": rows, "total": total, "page": page, "limit": limit}


@app.get("/api/cves/{cve_id}")
def get_cve(cve_id: str, enrich: bool = True) -> dict:
    cve_id = cve_id.upper()
    with db.session() as conn:
        findings = db.findings_for_cve(conn, cve_id)
        cached = db.get_cached_cve(conn, cve_id)
        assignment = None
        for a in db.list_assignments(conn):
            if a["cve_id"] == cve_id:
                assignment = a
                break

    if not findings and not cached:
        raise HTTPException(status_code=404, detail="CVE not found in the current scan")

    enrichment = cached
    if enrich and enrichment is None:
        try:
            enrichment = enrich_cve(cve_id)
            with db.session() as conn:
                db.cache_cve(conn, cve_id, enrichment)
        except Exception:  # pragma: no cover - network failures are non-fatal
            enrichment = None

    return {
        "cve_id": cve_id,
        "findings": findings,
        "enrichment": enrichment,
        "assignment": assignment,
    }


@app.get("/api/assignments")
def get_assignments() -> dict:
    with db.session() as conn:
        return {"items": db.list_assignments(conn)}


@app.post("/api/assignments")
def create_assignment(payload: AssignmentRequest, request: Request) -> dict:
    require_editor(request)
    target = payload.target_repo or config.PATCH_TARGET_REPO
    with db.session() as conn:
        finding = db.get_finding(
            conn, payload.cve_id.upper(), payload.package_name, spec_path=payload.spec_path
        )
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        record = db.create_assignment(
            conn, payload.cve_id.upper(), payload.package_name, target, payload.notes
        )
    return {
        "assignment": record,
        "workflow": "VULNEX -> Patch Automation queue -> AI Patch/Backport Agent -> "
                    "Security Review Agent -> PR Agent -> GitHub Pull Request",
        "target_repo": target,
    }


@app.patch("/api/assignments/{assignment_id}")
def patch_assignment(assignment_id: int, request: Request, status: str = Query(...)) -> dict:
    require_editor(request)
    with db.session() as conn:
        record = db.update_assignment(conn, assignment_id, status)
    if not record:
        raise HTTPException(status_code=404, detail="Assignment not found")
    return {"assignment": record}


@app.post("/api/assignments/{assignment_id}/comments")
def add_assignment_comment(
    assignment_id: int, payload: CommentRequest, request: Request
) -> dict:
    """Editor-only triage comment on a queued finding."""
    require_editor(request)
    body = (payload.body or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Comment body is required")
    with db.session() as conn:
        if not db.get_assignment(conn, assignment_id):
            raise HTTPException(status_code=404, detail="Assignment not found")
        comment = db.add_comment(
            conn, assignment_id, body, author=(payload.author or "editor").strip() or "editor"
        )
    return {"comment": comment}


# -- scan control -----------------------------------------------------------
@app.post("/api/scan")
def start_scan(request: Request, payload: ScanRequest | None = None) -> JSONResponse:
    require_editor(request)
    payload = payload or ScanRequest()
    options = ScanOptions(
        branches=payload.branches or list(config.DEFAULT_BRANCHES),
        packages=set(payload.packages) if payload.packages else None,
        limit=payload.limit,
        verify_blobs=payload.verify_blobs,
        enrich=payload.enrich,
    )
    started = manager.start(options)
    if not started:
        return JSONResponse(status_code=409, content={"detail": "A scan is already running"})
    return JSONResponse(status_code=202, content={"status": "started"})


@app.get("/api/scan/status")
def scan_status() -> dict:
    with db.session() as conn:
        latest = db.latest_scan(conn)
    return {"manager": manager.status(), "latest_scan": latest}


@app.get("/api/scans")
def scan_history() -> dict:
    with db.session() as conn:
        return {"items": db.scan_history(conn)}


@app.get("/api/methodology")
def methodology() -> dict:
    return {
        "sources": [
            {
                "name": "OSV.dev — Azure Linux advisories",
                "role": "Primary detection. Official Microsoft Azure Linux advisory data "
                        "with RPM version-release fixed events.",
                "url": "https://osv.dev/list?ecosystem=Azure%20Linux%3A3",
            },
            {"name": "NVD", "role": "CVSS severity, CWE and references.", "url": "https://nvd.nist.gov"},
            {"name": "MITRE CVE", "role": "Authoritative CVE identity and description.",
             "url": "https://cve.mitre.org"},
            {"name": "Red Hat Security Data", "role": "Corroboration, fixed versions and "
             "RPM package state.", "url": "https://access.redhat.com/security/data/metrics"},
            {"name": "GitHub Security Advisories", "role": "Corroboration and upstream fix "
             "locator.", "url": "https://github.com/advisories"},
            {"name": "Debian / Ubuntu / Alpine (via OSV)", "role": "Cross-distribution "
             "corroboration of CVE identifiers.", "url": "https://osv.dev"},
        ],
        "statuses": {
            "affected": "Version-range match confirms exposure and no distro backport exists.",
            "patched": "A Patch: entry in the .spec file backports the fix.",
            "false_positive": "A CVE-*.nopatch marker explicitly marks the CVE not applicable.",
            "unconfirmed": "Advisory mentions the package but range data is insufficient; "
                           "flagged for review.",
        },
        "range_matching": "RPM EVR comparison (rpmvercmp port) against OSV introduced/fixed "
                          "events, evaluated locally for traceability.",
        "patch_target_repo": config.PATCH_TARGET_REPO,
    }


# -- static frontend --------------------------------------------------------
if config.FRONTEND_DIR.exists():
    app.mount(
        "/",
        StaticFiles(directory=str(config.FRONTEND_DIR), html=True),
        name="frontend",
    )
