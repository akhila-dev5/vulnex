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
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, auth, config, db, triage
from .enrichment import enrich_cve
from .scanner import ScanOptions, run_scan
from .sources.vulnerabilitydata import FeedError, VulnerabilityDataSource

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
    title="Vulnex API",
    version=__version__,
    description="Vulnex Azure Linux CVE triage API.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
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
# The tool is read-only by default. A request presents its credential in the
# ``X-VULNEX-Key`` header and resolves to one of three roles:
#
#   viewer      anonymous: reads everything, writes nothing
#   admin       full triage (patch verdicts, disputes, comments, PR reference,
#               queueing work, starting scans). The credential is an opaque
#               session token minted by the GitHub callback — never a shared
#               static key and never a password.
#   automation  the machine key that may ONLY set the GitHub CVE PR
ROLE_VIEWER = config.ROLE_VIEWER
ROLE_ADMIN = config.ROLE_ADMIN
ROLE_AUTOMATION = config.ROLE_AUTOMATION

_CAPABILITIES = {
    ROLE_ADMIN: {
        "triage", "dispute", "comment", "scan", "assign", "patch_verdict", "set_pr",
    },
    ROLE_AUTOMATION: {"set_pr"},
    ROLE_VIEWER: set(),
}


def _presented_credential(request: Request) -> str | None:
    return request.headers.get("x-vulnex-key") or None


def resolve_role(request: Request) -> str:
    """Resolve the caller's role from the presented credential.

    An admin session token wins; anything else is treated as a machine key and
    can only ever be the narrowly-scoped automation identity. A missing or
    unknown credential is always read-only.
    """
    credential = _presented_credential(request)
    if not credential:
        return ROLE_VIEWER
    if auth.sessions.get(credential):
        return ROLE_ADMIN
    return config.role_for_key(credential)


def capabilities(role: str) -> dict:
    granted = _CAPABILITIES.get(role, set())
    return {
        "write_enabled": role == ROLE_ADMIN,
        "can_comment": "comment" in granted,
        "can_dispute": "dispute" in granted,
        "can_triage": "triage" in granted,
        "can_scan": "scan" in granted,
        "can_set_patch_verdict": "patch_verdict" in granted,
        "can_set_pr": "set_pr" in granted,
    }


def require_admin(request: Request) -> str:
    """Raise 401 unless the caller is the admin identity."""
    role = resolve_role(request)
    if role != ROLE_ADMIN:
        raise HTTPException(
            status_code=401,
            detail="Read-only access: this action needs an admin sign-in. "
                   "Sign in with Google and retry.",
        )
    return role


def require_pr_setter(request: Request) -> str:
    """Raise 401 unless the caller may set the GitHub CVE PR.

    Only the admin and the narrowly-scoped ``automation`` identity qualify; a
    viewer and any other caller are refused.
    """
    role = resolve_role(request)
    if "set_pr" not in _CAPABILITIES.get(role, set()):
        raise HTTPException(
            status_code=401,
            detail="Setting the GitHub CVE PR needs the automation identity or admin.",
        )
    return role


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
    cve_id: str | None = None
    branch: str = ""
    spec_path: str = ""
    author: str | None = None


class FindingRef(BaseModel):
    cve_id: str
    branch: str = ""
    spec_path: str = ""


class DisputeRequest(FindingRef):
    reason: str


class GithubPRRequest(FindingRef):
    number: str
    url: str = ""


class PatchVerdictRequest(FindingRef):
    final_verdict: str = ""
    patch_link: str = ""
    available_since: str = ""


# -- read endpoints ---------------------------------------------------------
@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "time": _now()}


@app.get("/api/role")
def get_role(request: Request) -> dict:
    """Which tier the caller is in, so the UI can show only permitted actions.

    Also tells the sign-in dialog which methods this deployment actually offers,
    so it never shows a button that cannot work.
    """
    role = resolve_role(request)
    session = auth.sessions.get(_presented_credential(request))
    return {
        "role": role,
        "identity": config.identity_for(role),
        "methods": {
            "google": config.google_login_configured(),
            "google_email": config.ADMIN_EMAIL_ALLOWLIST,
        },
        "expires_at": session["expires_at"] if session else None,
        **capabilities(role),
    }


# -- authentication ---------------------------------------------------------
def _callback_url(request: Request) -> str:
    """The Google OAuth redirect URI (override it behind a reverse proxy)."""
    return config.GOOGLE_OAUTH_REDIRECT or str(request.url_for("auth_google_callback"))


@app.post("/api/auth/logout")
def auth_logout(request: Request) -> dict:
    """Drop the caller's session token."""
    return {"signed_out": auth.sessions.drop(_presented_credential(request))}


@app.get("/api/auth/google")
def auth_google(request: Request) -> RedirectResponse:
    """Start Google sign-in for the configured administrator."""
    if not config.google_login_configured():
        raise HTTPException(status_code=503, detail="Google sign-in is not configured.")
    state = auth.new_oauth_state()
    return RedirectResponse(auth.google_authorize_url(_callback_url(request), state))


@app.get("/api/auth/google/callback", name="auth_google_callback")
def auth_google_callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
    """Finish Google sign-in after checking the provider-verified email."""
    if not config.google_login_configured():
        raise HTTPException(status_code=503, detail="Google sign-in is not configured.")
    if not auth.consume_oauth_state(state):
        raise HTTPException(status_code=400, detail="The Google sign-in link expired. Please try again.")
    user = auth.google_exchange(code, _callback_url(request))
    email = (user or {}).get("email")
    verified = (user or {}).get("email_verified") is True
    if not auth.google_login_allowed(email, verified):
        raise HTTPException(status_code=403, detail="This verified Google account is not the configured administrator.")
    identity = {**config.identity_for(ROLE_ADMIN), "identity": email, "email": email}
    token, _ = auth.sessions.create(identity, method="google")
    return RedirectResponse(f"/#vulnex_token={token}")


@app.get("/api/stats")
def get_stats() -> dict:
    with db.session() as conn:
        data = db.stats(conn)
    data["repository"] = config.repository_metadata()
    data["roles"] = config.roles_metadata()
    return data


def _decorate_findings(
    conn,
    findings: list[dict],
    package: dict | None = None,
    enrichment: dict | None = None,
) -> list[dict]:
    """Attach triage state, patch availability, links and the Deep view."""
    for finding in findings:
        finding["triage"] = db.get_triage(
            conn, finding["cve_id"], finding.get("branch", ""), finding.get("spec_path", "")
        )
        triage.decorate_finding(finding, package, enrichment)
    return findings


def _package_for(conn, finding: dict) -> dict | None:
    """Resolve the owning package row so Deep can name the source tarball."""
    return db.get_package(
        conn, finding.get("package_name", ""), finding.get("branch"),
        spec_path=finding.get("spec_path"),
    )


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
        if pkg:
            # Open exposures only — a package page never lists what is fixed.
            pkg["findings"] = [
                f for f in pkg.get("findings", [])
                if f.get("status") == config.OPEN_STATUS
            ]
            _decorate_findings(conn, pkg["findings"], package=pkg)
    if not pkg:
        raise HTTPException(status_code=404, detail="Package not found")
    return pkg


@app.get("/api/findings")
def get_findings(
    severity: str = "",
    search: str = "",
    package: str = "",
    branch: str = "",
    page: int = 1,
    limit: int = Query(100, ge=1, le=1000),
    patch_state: str = "",
    triage_status: str = "",
    resolution_status: str = "",
    owner: str = "",
    fixed_version: str = "",
) -> dict:
    """List open exposures with source-backed filters and persisted triage metadata.

    Patch filters describe whether a candidate patch reference was found. They
    do not assert that a patch is verified or that a fix has shipped.
    """
    extra_filters = any((patch_state, triage_status, resolution_status, owner, fixed_version))
    with db.session() as conn:
        if not extra_filters:
            rows, total = db.list_findings(
                conn,
                status=config.OPEN_STATUS,
                severity=severity,
                search=search,
                package=package,
                branch=branch,
                limit=limit,
                offset=(page - 1) * limit,
            )
            _decorate_findings(conn, rows)
            return {"items": rows, "total": total, "page": page, "limit": limit}

        # Workflow and patch evidence are derived after joining persisted triage
        # data, so apply these filters before pagination rather than filtering a
        # single page in the browser.
        candidates: list[dict] = []
        offset = 0
        batch_size = 1000
        while True:
            batch, source_total = db.list_findings(
                conn,
                status=config.OPEN_STATUS,
                severity=severity,
                search=search,
                package=package,
                branch=branch,
                limit=batch_size,
                offset=offset,
            )
            if not batch:
                break
            _decorate_findings(conn, batch)
            candidates.extend(batch)
            offset += len(batch)
            if offset >= source_total:
                break

        filtered = []
        for finding in candidates:
            triage_record = finding.get("triage") or {}
            patch = finding.get("patch_availability") or {}
            if triage_status and str(triage_record.get("triage_status") or "open").lower() != triage_status.lower():
                continue
            if resolution_status and str(triage_record.get("resolution_status") or finding.get("status") or "").lower() != resolution_status.lower():
                continue
            if owner and owner.lower() not in str(triage_record.get("owner") or "").lower():
                continue
            if fixed_version and fixed_version.lower() not in str(finding.get("fixed_version") or "").lower():
                continue
            if patch_state == "available" and not patch.get("available"):
                continue
            if patch_state == "unavailable" and (not patch.get("applicable") or patch.get("available")):
                continue
            if patch_state == "unknown" and patch.get("applicable") is not False:
                continue
            filtered.append(finding)

        total = len(filtered)
        start_at = max(page - 1, 0) * limit
        return {"items": filtered[start_at:start_at + limit], "total": total, "page": page, "limit": limit}


@app.get("/api/cves/{cve_id}")
def get_cve(cve_id: str, enrich: bool = True) -> dict:
    cve_id = cve_id.upper()
    with db.session() as conn:
        # A CVE page only exists while the CVE is still open here: once every
        # branch has backported it there is nothing left to triage.
        findings = [
            f for f in db.findings_for_cve(conn, cve_id)
            if f.get("status") == config.OPEN_STATUS
        ]
        cached = db.get_cached_cve(conn, cve_id)
        assignment = None
        for a in db.list_assignments(conn):
            if a["cve_id"] == cve_id:
                assignment = a
                break

    if not findings:
        raise HTTPException(status_code=404, detail="CVE not found in the current scan")

    enrichment = cached
    if enrich and enrichment is None:
        try:
            enrichment = enrich_cve(cve_id)
            with db.session() as conn:
                db.cache_cve(conn, cve_id, enrichment)
        except Exception:  # pragma: no cover - network failures are non-fatal
            enrichment = None

    with db.session() as conn:
        for finding in findings:
            finding["triage"] = db.get_triage(
                conn, finding["cve_id"], finding.get("branch", ""),
                finding.get("spec_path", ""),
            )
            triage.decorate_finding(finding, _package_for(conn, finding), enrichment)

    return {
        "cve_id": cve_id,
        "findings": findings,
        "enrichment": enrichment,
        "assignment": assignment,
        "links": triage.website_links(cve_id),
    }


@app.get("/api/cves/{cve_id}/deep")
def get_cve_deep(cve_id: str, branch: str = "", spec: str = "") -> dict:
    """The Deep view: files inside the package tarball that this CVE touches."""
    cve_id = cve_id.upper()
    with db.session() as conn:
        results = [
            f for f in db.findings_for_cve(conn, cve_id)
            if f.get("status") == config.OPEN_STATUS
        ]
        if branch:
            results = [f for f in results if f.get("branch") == branch]
        if spec:
            results = [f for f in results if f.get("spec_path") == spec]
        finding = results[0] if results else None
        if finding is None:
            raise HTTPException(status_code=404, detail="CVE/package/branch combination not found in the current scan")
        return triage.deep_view(finding, _package_for(conn, finding))


# -- VulnerabilityData feed (pre-computed NVD inventory) ---------------------
def _vuln_data_source() -> VulnerabilityDataSource:
    return VulnerabilityDataSource()


@app.get("/api/vulnerability-data")
def get_vulnerability_data(refresh: bool = False) -> dict:
    """Summary of the NVD inventory the VulnerabilityData repo publishes.

    It is produced from the azurelinux-test cgmanifest.json x NVD feeds, so it
    covers exactly the versions registered in the manifest. ``?refresh=true``
    re-fetches the feed instead of using the on-disk cache.
    """
    try:
        return _vuln_data_source().summary(refresh=refresh)
    except FeedError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/api/vulnerability-data/packages")
def get_vulnerability_data_packages(
    search: str = "",
    page: int = 1,
    limit: int = Query(50, ge=1, le=500),
    refresh: bool = False,
) -> dict:
    """Paged package inventory from the VulnerabilityData feed."""
    try:
        packages = _vuln_data_source().packages(refresh=refresh)
    except FeedError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    if search:
        needle = search.lower()
        packages = [p for p in packages if needle in (p.get("name") or "").lower()]
    total = len(packages)
    start = (page - 1) * limit
    return {
        "items": packages[start:start + limit],
        "total": total,
        "page": page,
        "limit": limit,
    }


@app.get("/api/vulnerability-data/packages/{name}")
def get_vulnerability_data_package(name: str, refresh: bool = False) -> dict:
    """One package's NVD/CVE inventory as published by VulnerabilityData."""
    try:
        pkg = _vuln_data_source().package(name, refresh=refresh)
    except FeedError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    if pkg is None:
        raise HTTPException(
            status_code=404, detail="Package not found in the VulnerabilityData feed"
        )
    return pkg


@app.get("/api/triage")
def get_triage_list(
    status: str = config.OPEN_STATUS,
    search: str = "",
    page: int = 1,
    limit: int = Query(50, ge=1, le=200),
) -> dict:
    """Open exposures joined with their triage record, for the triage table."""
    with db.session() as conn:
        rows, total = db.list_triage(
            conn, status=config.OPEN_STATUS, search=search,
            limit=limit, offset=(page - 1) * limit,
        )
        for row in rows:
            triage.decorate_finding(row, None)
    return {"items": rows, "total": total, "page": page, "limit": limit}


@app.get("/api/triage/comments")
def get_triage_comments(
    cve_id: str = Query(..., min_length=4, max_length=32),
    branch: str = "",
    spec_path: str = "",
) -> dict:
    """Read the persisted comment/dispute history for one finding."""
    with db.session() as conn:
        comments = db.finding_comments(conn, cve_id.upper(), branch, spec_path)
    return {"items": comments, "total": len(comments)}


@app.post("/api/triage/comment")
def add_triage_comment(payload: CommentRequest, request: Request) -> dict:
    """Admin-only triage comment on a specific finding."""
    role = require_admin(request)
    body = (payload.body or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Comment body is required")
    if not payload.cve_id:
        raise HTTPException(status_code=400, detail="cve_id is required")
    author = (payload.author or config.ADMIN_IDENTITY).strip()
    with db.session() as conn:
        comment = db.add_finding_comment(
            conn, payload.cve_id.upper(), payload.branch, payload.spec_path, body, author
        )
    return {"comment": comment, "role": role}


@app.post("/api/triage/dispute")
def raise_dispute(payload: DisputeRequest, request: Request) -> dict:
    """Admin-only dispute. The reason lands under the triage comments."""
    require_admin(request)
    reason = (payload.reason or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="A dispute needs a reason")
    cve_id = payload.cve_id.upper()
    with db.session() as conn:
        comment = db.add_finding_comment(
            conn, cve_id, payload.branch, payload.spec_path, reason,
            config.ADMIN_IDENTITY, kind="dispute",
        )
        record = db.upsert_triage(
            conn, cve_id, payload.branch, payload.spec_path,
            triage_status="disputed", resolution_status="in_progress",
        )
    return {"comment": comment, "triage": record}


@app.post("/api/triage/github-pr")
def set_github_pr(payload: GithubPRRequest, request: Request) -> dict:
    """Set the GitHub CVE PR. Allowed for the automation identity and admin."""
    role = require_pr_setter(request)
    number = (payload.number or "").strip().lstrip("#")
    if not number.isdigit():
        raise HTTPException(status_code=400, detail="PR number must contain digits only")
    cve_id = payload.cve_id.upper()
    url = (payload.url or "").strip() or (
        f"https://github.com/{config.PATCH_TARGET_REPO}/pull/{number}"
    )
    # A URL is only an association, not proof of a fix. Restrict it to a
    # canonical GitHub pull-request URL and require the path number to match.
    import re
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/" + re.escape(number) + r"/?", url):
        raise HTTPException(status_code=400, detail="Use a GitHub pull request URL whose number matches the PR number field")
    identity = config.identity_for(role).get("identity") or role
    with db.session() as conn:
        record = db.upsert_triage(
            conn,
            cve_id,
            payload.branch,
            payload.spec_path,
            github_pr_number=number,
            github_pr_url=url,
            github_pr_set_by=identity,
            github_pr_set_at=db.utcnow(),
            resolution_status="in_progress",
            owner=config.ADMIN_EMAIL or config.ADMIN_IDENTITY,
        )
    return {"triage": record, "role": role, "identity": identity}


@app.post("/api/triage/patch")
def set_patch_verdict(payload: PatchVerdictRequest, request: Request) -> dict:
    """Admin-only override of the patch availability verdict/link."""
    require_admin(request)
    cve_id = payload.cve_id.upper()
    with db.session() as conn:
        record = db.upsert_triage(
            conn,
            cve_id,
            payload.branch,
            payload.spec_path,
            final_verdict=payload.final_verdict.strip(),
            patch_link=payload.patch_link.strip(),
            available_since=payload.available_since.strip(),
        )
    return {"triage": record}


# -- assignment queue -------------------------------------------------------
@app.get("/api/assignments")
def get_assignments() -> dict:
    with db.session() as conn:
        return {"items": db.list_assignments(conn)}


@app.post("/api/assignments")
def create_assignment(payload: AssignmentRequest, request: Request) -> dict:
    require_admin(request)
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
    require_admin(request)
    with db.session() as conn:
        record = db.update_assignment(conn, assignment_id, status)
    if not record:
        raise HTTPException(status_code=404, detail="Assignment not found")
    return {"assignment": record}


@app.post("/api/assignments/{assignment_id}/comments")
def add_assignment_comment(
    assignment_id: int, payload: CommentRequest, request: Request
) -> dict:
    """Admin-only triage comment on a queued finding."""
    require_admin(request)
    body = (payload.body or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Comment body is required")
    with db.session() as conn:
        if not db.get_assignment(conn, assignment_id):
            raise HTTPException(status_code=404, detail="Assignment not found")
        comment = db.add_comment(
            conn, assignment_id, body,
            author=(payload.author or config.ADMIN_IDENTITY).strip(),
        )
    return {"comment": comment}


# -- scan control -----------------------------------------------------------
@app.post("/api/scan")
def start_scan(request: Request, payload: ScanRequest | None = None) -> JSONResponse:
    require_admin(request)
    payload = payload or ScanRequest()
    options = ScanOptions(
        branches=["3.0"],
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


# -- static frontend --------------------------------------------------------
# Prefer the Vite build when deployed; fall back to the old static frontend before build.
_REACT_BUILD_DIR = config.FRONTEND_DIR / "dist"
_STATIC_FRONTEND_DIR = _REACT_BUILD_DIR if (_REACT_BUILD_DIR / "index.html").is_file() else config.FRONTEND_DIR
if _STATIC_FRONTEND_DIR.exists():
    app.mount(
        "/",
        StaticFiles(directory=str(_STATIC_FRONTEND_DIR), html=True),
        name="frontend",
    )
