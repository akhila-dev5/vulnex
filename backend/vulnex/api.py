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
# The tool is read-only by default. A request presents its credential in the
# ``X-VULNEX-Key`` header and resolves to one of three roles:
#
#   viewer      anonymous: reads everything, writes nothing
#   admin       full triage (patch verdicts, disputes, comments, PR reference,
#               queueing work, starting scans). The credential is an opaque
#               session token minted by ``/api/auth/login`` from an email +
#               password, or by the GitHub callback — never a shared static key.
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
                   "Sign in with your email and password and retry.",
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
            "password": config.password_login_configured(),
            "github": config.github_login_configured(),
            "github_login": config.ADMIN_GITHUB,
        },
        "expires_at": session["expires_at"] if session else None,
        **capabilities(role),
    }


# -- authentication ---------------------------------------------------------
class LoginRequest(BaseModel):
    email: str = ""
    password: str = ""


def _callback_url(request: Request) -> str:
    """The GitHub OAuth redirect URI (override it behind a reverse proxy)."""
    return config.GITHUB_OAUTH_REDIRECT or str(request.url_for("auth_github_callback"))


@app.post("/api/auth/login")
def auth_login(payload: LoginRequest) -> dict:
    """Sign in as admin with email + password and mint a session token."""
    if not config.password_login_configured():
        raise HTTPException(
            status_code=503,
            detail="Password sign-in is not configured on this server. Set "
                   "VULNEX_ADMIN_EMAIL and VULNEX_ADMIN_PASSWORD_HASH.",
        )
    if not auth.password_login(payload.email, payload.password):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    token, session = auth.sessions.create(
        config.identity_for(ROLE_ADMIN), method="password"
    )
    return {
        "token": token,
        "role": ROLE_ADMIN,
        "identity": session["identity"],
        "method": "password",
        "expires_at": session["expires_at"],
        **capabilities(ROLE_ADMIN),
    }


@app.post("/api/auth/logout")
def auth_logout(request: Request) -> dict:
    """Drop the caller's session token (a no-op for the machine key)."""
    return {"signed_out": auth.sessions.drop(_presented_credential(request))}


@app.get("/api/auth/github")
def auth_github(request: Request) -> RedirectResponse:
    """Start GitHub sign-in for the admin allow-list."""
    if not config.github_login_configured():
        raise HTTPException(
            status_code=503,
            detail="GitHub sign-in is not configured on this server. Set "
                   "GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_CLIENT_SECRET.",
        )
    state = auth.new_oauth_state()
    return RedirectResponse(auth.github_authorize_url(_callback_url(request), state))


@app.get("/api/auth/github/callback", name="auth_github_callback")
def auth_github_callback(
    request: Request, code: str = "", state: str = ""
) -> RedirectResponse:
    """Finish GitHub sign-in and hand the SPA its session token."""
    if not config.github_login_configured():
        raise HTTPException(status_code=503, detail="GitHub sign-in is not configured.")
    if not auth.consume_oauth_state(state):
        raise HTTPException(
            status_code=400, detail="The GitHub sign-in link expired. Please try again."
        )
    user = auth.github_exchange(code, _callback_url(request))
    login = (user or {}).get("login")
    if not auth.github_login_allowed(login):
        raise HTTPException(
            status_code=403,
            detail="This GitHub account is not allowed to sign in as admin.",
        )
    identity = {**config.identity_for(ROLE_ADMIN), "identity": login or config.ADMIN_IDENTITY}
    token, _ = auth.sessions.create(identity, method="github")
    # The token rides in the fragment, so it never reaches a server log or a
    # Referer header on the way back to the dashboard.
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
) -> dict:
    """Open exposures only.

    There is deliberately no ``status`` filter: the site only ever serves
    findings that are still ``affected``, never the CVEs this distro has already
    fixed or ruled out. A stray ``?status=`` is simply ignored.
    """
    with db.session() as conn:
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
        finding = db.get_finding(conn, cve_id, spec_path=spec or None) if spec else None
        if finding is not None and finding.get("status") != config.OPEN_STATUS:
            finding = None
        if finding is None:
            results = [
                f for f in db.findings_for_cve(conn, cve_id)
                if f.get("status") == config.OPEN_STATUS
            ]
            if branch:
                results = [f for f in results if f.get("branch") == branch] or results
            finding = results[0] if results else None
        if finding is None:
            raise HTTPException(status_code=404, detail="CVE not found in the current scan")
        return triage.deep_view(finding, _package_for(conn, finding))


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
    if not number:
        raise HTTPException(status_code=400, detail="PR number is required")
    cve_id = payload.cve_id.upper()
    url = (payload.url or "").strip() or (
        f"https://github.com/{config.PATCH_TARGET_REPO}/pull/{number}"
    )
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


# -- static frontend --------------------------------------------------------
if config.FRONTEND_DIR.exists():
    app.mount(
        "/",
        StaticFiles(directory=str(config.FRONTEND_DIR), html=True),
        name="frontend",
    )
