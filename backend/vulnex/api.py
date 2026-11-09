"""VULNEX FastAPI application.

Serves the JSON API consumed by the dashboard and (when present) the built
static frontend. A single-process background thread runs scans so "Scan Now"
works without any external queue or paid infrastructure.
"""

from __future__ import annotations

import logging
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, auth, cache, config, db, fixed_cves, triage
from .enrichment import enrich_cve
from .pgcompat import DatabaseUnavailable
from .sqlite_import import backfill_first_seen, seed_if_empty
from .scanner import ScanOptions, run_scan
from .sources.vulnerabilitydata import FeedError, VulnerabilityDataSource

_log = logging.getLogger("uvicorn.error")
_seeded = False


def _prepare_database(conn) -> None:
    """Apply the schema and, on a brand-new Postgres, load the bundled snapshot once."""
    global _seeded
    db.init_db(conn)
    if getattr(conn, "dialect", "") != "postgres" or _seeded:
        return
    if os.environ.get("VULNEX_SEED_SNAPSHOT", "1") == "0":
        _seeded = True
        return
    try:
        result = seed_if_empty(conn, config.DB_PATH)
    except Exception as exc:  # never let a bad snapshot stop the service
        conn.rollback()
        _log.error("Could not load the bundled snapshot into Postgres: %s", exc)
        return
    _seeded = True
    try:
        filled = backfill_first_seen(conn, config.DB_PATH)
        if filled:
            _log.info("Backfilled first-scanned dates from the snapshot (%s rows checked)", filled)
    except Exception as exc:
        conn.rollback()
        _log.error("Could not backfill first-scanned dates: %s", exc)
    if result.get("seeded"):
        _log.info("Loaded bundled scan snapshot into Postgres: %s", result["copied"])


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Make sure the snapshot DB carries the current schema before serving.

    An unreachable database must not kill the process: Render would restart it in
    a loop with "no open ports". Instead the app starts, says why in the log, and
    ``/api/health`` reports 503 until the database answers (and applies the schema
    then), so a bad ``DATABASE_URL`` is visible and a good previous deploy keeps
    serving.
    """
    try:
        conn = db.connect()
        try:
            _prepare_database(conn)
        finally:
            conn.close()
    except DatabaseUnavailable as exc:
        logging.getLogger("uvicorn.error").error("Database unavailable at startup: %s", exc)
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
# The CVE list is a few hundred KB of repetitive JSON; compressing it makes it
# roughly ten times smaller on the wire.
app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.middleware("http")
async def _drop_cache_after_writes(request: Request, call_next):
    response = await call_next(request)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        cache.clear()
    return response


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
            cache.clear()
            with self._lock:
                self.state["running"] = False
                self.state["finished_at"] = _now()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self.state)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _branches_for_filter(branch: str) -> list[str] | None:
    """Map release labels to branch names available in the user's azurelinux-test fork."""
    # Only exact stable branches are included in the release filters.
    aliases = {
        "3.0": ["3.0"],
        "4.0": ["4.0"],
    }
    return aliases.get(branch)


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
ROLE_DEVELOPER = config.ROLE_DEVELOPER

_CAPABILITIES = {
    ROLE_ADMIN: {
        "triage", "dispute", "comment", "scan", "assign", "patch_verdict", "set_pr",
        "approve_dispute", "rescore", "claim",
    },
    # Developers: set a GitHub PR, comment and raise disputes. Approving a dispute,
    # assigning and setting a patch verdict stay with the administrator.
    ROLE_DEVELOPER: {"comment", "dispute", "set_pr", "claim"},
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
    session = auth.sessions.get(credential)
    if session:
        return session.get("role") or ROLE_ADMIN
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
        "can_assign": "assign" in granted,
        "can_approve_dispute": "approve_dispute" in granted,
        "can_rescore": "rescore" in granted,
        "can_claim": "claim" in granted,
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


def require_capability(request: Request, capability: str, what: str) -> str:
    """Raise 401 unless the caller's role grants ``capability``; returns the role."""
    role = resolve_role(request)
    if capability not in _CAPABILITIES.get(role, set()):
        raise HTTPException(
            status_code=401,
            detail=f"Sign in with Google to {what}. Read-only visitors cannot do this.",
        )
    return role


def actor_identity(request: Request, role: str) -> str:
    """Who to record as the author of a change: the signed-in email, else the role's name."""
    session = auth.sessions.get(_presented_credential(request))
    email = ((session or {}).get("identity") or {}).get("email")
    return email or config.identity_for(role).get("identity") or role


def require_pr_setter(request: Request) -> str:
    """Raise 401 unless the caller may set the GitHub CVE PR.

    The admin, developers and the narrowly-scoped ``automation`` identity qualify;
    a viewer and any other caller are refused.
    """
    role = resolve_role(request)
    if "set_pr" not in _CAPABILITIES.get(role, set()):
        raise HTTPException(
            status_code=401,
            detail="Setting the GitHub CVE PR needs a developer or admin sign-in.",
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
    assignee_email: str = ""


ASSIGNABLE_EMAILS = {
    "gurujuakhila.dev@gmail.com",
    "dev1.vulnex@gmail.com",
    "dev2.vulnex@gmail.com",
    "dev3.vulnex@gmail.com",
}


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
    first_unaffected_version: str = ""
    never_applicable: bool = False


class GithubPRRequest(FindingRef):
    number: str
    url: str = ""


class RescoreRequest(BaseModel):
    severity: str
    cvss_score: float | None = None
    reason: str = ""


class PatchVerdictRequest(FindingRef):
    final_verdict: str = ""
    patch_link: str = ""
    available_since: str = ""


# -- read endpoints ---------------------------------------------------------
@app.exception_handler(DatabaseUnavailable)
async def _database_unavailable(_request: Request, exc: DatabaseUnavailable) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": f"Database unavailable. {exc}"})


@app.get("/api/health")
def health():
    body = {"status": "ok", "version": __version__, "time": _now()}
    if config.DATABASE_URL:
        try:
            conn = db.connect()
            try:
                _prepare_database(conn)  # schema + first-run data, if startup could not
                conn.execute("SELECT 1")
            finally:
                conn.close()
        except DatabaseUnavailable as exc:
            return JSONResponse(
                status_code=503,
                content={**body, "status": "unavailable", "database": "unreachable", "detail": str(exc)},
            )
        body["database"] = "postgres"
    return body


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
        "identity": (
            {**config.identity_for(role), "identity": actor_identity(request, role),
             "email": (session or {}).get("identity", {}).get("email", config.identity_for(role).get("email", ""))}
        ),
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
    role = auth.google_role_for(email, verified)
    if role is None:
        raise HTTPException(
            status_code=403,
            detail="This Google account is not allowed to sign in. Ask the administrator to add it.",
        )
    identity = {**config.identity_for(role), "identity": email, "email": email}
    token, _ = auth.sessions.create(identity, method="google", role=role)
    return RedirectResponse(f"/#vulnex_token={token}")


@app.get("/api/stats")
def get_stats(branch: str = "") -> dict:
    if branch and not _branches_for_filter(branch):
        raise HTTPException(status_code=400, detail="Choose stable branch 3.0 or 4.0.")
    def compute() -> dict:
        with db.session() as conn:
            data = db.stats(conn, branch=branch or None)
        data["repository"] = config.repository_metadata()
        data["roles"] = config.roles_metadata()
        data["selected_branch"] = branch or None
        return data

    return cache.cached(("stats", branch), compute)


def _decorate_findings(
    conn,
    findings: list[dict],
    package: dict | None = None,
    enrichment: dict | None = None,
    slim: bool = False,
) -> list[dict]:
    """Attach triage state, patch availability, links and the Deep view."""
    assignments = {
        (item.get("cve_id"), item.get("package_name")): item
        for item in db.list_assignments(conn)
    }
    records = db.triage_index(conn)  # one query, not one per finding
    disputes = db.dispute_index(conn)
    for finding in findings:
        finding["triage"] = records.get(
            (finding["cve_id"], finding.get("branch") or "", finding.get("spec_path") or "")
        )
        finding["assignment"] = assignments.get((finding.get("cve_id"), finding.get("package_name")))
        finding["dispute"] = disputes.get(
            (finding["cve_id"], finding.get("branch") or "", finding.get("spec_path") or "")
        )
        # List rows stay light: tracker links and the Deep view are fetched when a
        # CVE or Deep inspection is opened, not shipped for every row.
        triage.decorate_finding(
            finding, package, enrichment, include_links=not slim, include_deep=not slim
        )
        if slim:
            finding.pop("raw_sources", None)
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
            conn, search=search, branch=branch if not _branches_for_filter(branch) else "",
            branches=_branches_for_filter(branch), limit=limit, offset=(page - 1) * limit
        )
    return {"items": rows, "total": total, "page": page, "limit": limit}


@app.get("/api/packages/{name}")
def get_package(name: str, branch: str | None = None, spec: str | None = None) -> dict:
    with db.session() as conn:
        pkg = db.get_package(conn, name, branch, spec_path=spec)
        if pkg:
            # Keep every CVE found in the selected package spec, including
            # backported, explicitly-not-affected, and unconfirmed records.
            # The dashboard must retain these rows for review and assignment.
            _decorate_findings(conn, pkg["findings"], package=pkg)
    if not pkg:
        raise HTTPException(status_code=404, detail="Package not found")
    return pkg


@app.get("/api/findings")
def get_findings(
    severity: str = "",
    status: str = "",
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
    """List all CVE findings from the selected stable branch.

    Findings include affected, patched, explicitly-not-affected, and
    unconfirmed records. Keeping fixed/backported CVEs visible is necessary
    for triage history, details, and assignment. Pass status to narrow the
    scanner status when a consumer specifically wants one category.

    Patch filters describe whether a candidate patch reference was found; they
    do not assert that a patch is verified or that a fix has shipped.
    """
    def compute() -> dict:
        branches = _branches_for_filter(branch)
        base = dict(
            status=status,
            severity=severity,
            search=search,
            package=package,
            branch=branch if not branches else "",
            branches=branches,
            triage_status=triage_status,
            resolution_status=resolution_status,
            owner=owner,
            fixed_version=fixed_version,
        )
        with db.session() as conn:
            if not patch_state:
                # Everything is filtered and paged in SQL; only the visible page
                # is decorated.
                rows, total = db.list_findings(
                    conn, **base, limit=limit, offset=(max(page, 1) - 1) * limit
                )
                _decorate_findings(conn, rows, slim=True)
                return {"items": rows, "total": total, "page": page, "limit": limit}

            # Patch availability is derived from enrichment, so it can only be
            # judged after decorating. Narrow with SQL first, then filter the rest.
            rows, _ = db.list_findings(conn, **base, limit=1_000_000, offset=0)
            _decorate_findings(conn, rows, slim=True)

        want = patch_state == "available"
        # "Patch not available" means no candidate patch was found, including
        # findings where patch applicability is not established.
        filtered = [
            f for f in rows if bool((f.get("patch_availability") or {}).get("available")) == want
        ] if patch_state in ("available", "unavailable") else rows
        start_at = max(page - 1, 0) * limit
        return {
            "items": filtered[start_at:start_at + limit],
            "total": len(filtered),
            "page": page,
            "limit": limit,
        }

    key = ("findings", severity, status, search, package, branch, page, limit,
           patch_state, triage_status, resolution_status, owner, fixed_version)
    return cache.cached(key, compute)


def _older_than_a_day(stamp: str | None) -> bool:
    try:
        then = datetime.fromisoformat((stamp or "").replace("Z", "+00:00"))
    except ValueError:
        return True
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - then).total_seconds() > 86400


@app.get("/api/cves/{cve_id}")
def get_cve(cve_id: str, enrich: bool = True) -> dict:
    cve_id = cve_id.upper()
    with db.session() as conn:
        # Detail pages must remain available for every finding status.
        # A backported or ruled-out CVE still needs evidence, history, and
        # assignment visibility in the dashboard.
        findings = db.findings_for_cve(conn, cve_id)
        cached = db.get_cached_cve(conn, cve_id)
        assignment = None
        for a in db.list_assignments(conn):
            if a["cve_id"] == cve_id:
                assignment = a
                break

    if not findings:
        raise HTTPException(status_code=404, detail="CVE not found in the current scan")

    enrichment = cached
    if enrich and cached and cached.get("cvss_score") is None and _older_than_a_day(cached.get("_fetched_at")):
        enrichment = None  # no score last time; the sources may have one by now
    if enrich and enrichment is None:
        try:
            enrichment = enrich_cve(cve_id)
            with db.session() as conn:
                db.cache_cve(conn, cve_id, enrichment)
        except Exception:  # pragma: no cover - network failures are non-fatal
            enrichment = cached

    with db.session() as conn:
        disputes = db.dispute_index(conn)
        for finding in findings:
            finding["dispute"] = disputes.get(
                (finding["cve_id"], finding.get("branch") or "", finding.get("spec_path") or "")
            )
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
        results = db.findings_for_cve(conn, cve_id)
        if branch:
            results = [f for f in results if f.get("branch") == branch]
        if spec:
            results = [f for f in results if f.get("spec_path") == spec]
        finding = results[0] if results else None
        if finding is None:
            raise HTTPException(status_code=404, detail="CVE/package/branch combination not found in the current scan")
        return triage.deep_view(finding, _package_for(conn, finding))


@app.get("/api/fixed-cves")
def get_fixed_cves(branch: str = "3.0") -> dict:
    """Scanned CVEs already fixed in a spec, with the version-release they shipped in.

    This is the ledger published to VulnerabilityData. It is read-only and
    separate from patch availability (which concerns upstream patches only).
    """
    conn = db.connect()
    try:
        return fixed_cves.build_ledger(conn, branch)
    finally:
        conn.close()


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
    """Triage comment on a specific finding (administrator or developer)."""
    role = require_capability(request, "comment", "comment on a finding")
    body = (payload.body or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Comment body is required")
    if not payload.cve_id:
        raise HTTPException(status_code=400, detail="cve_id is required")
    author = actor_identity(request, role)
    with db.session() as conn:
        comment = db.add_finding_comment(
            conn, payload.cve_id.upper(), payload.branch, payload.spec_path, body, author
        )
    return {"comment": comment, "role": role}


def _apply_approved_dispute(conn, dispute: dict) -> dict:
    """What approval does: the reason joins the package's history and it is marked Disputed."""
    comment = db.add_finding_comment(
        conn, dispute["cve_id"], dispute["branch"], dispute["spec_path"],
        dispute["reason"], dispute.get("requested_by") or "developer", kind="dispute",
    )
    record = db.upsert_triage(
        conn, dispute["cve_id"], dispute["branch"], dispute["spec_path"],
        triage_status="disputed", resolution_status="disputed",
        package_name=dispute.get("package_name") or "",
    )
    return {"comment": comment, "triage": record}


@app.post("/api/triage/dispute")
def raise_dispute(payload: DisputeRequest, request: Request) -> dict:
    """Raise a dispute. A developer's request waits for admin approval; the admin's own is approved."""
    role = require_capability(request, "dispute", "raise a dispute")
    reason = (payload.reason or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="A dispute needs a reason")
    if not payload.cve_id:
        raise HTTPException(status_code=400, detail="cve_id is required")
    version = (payload.first_unaffected_version or "").strip()
    if payload.never_applicable:
        reason += "\nApplicability: Never Applicable"
    elif version:
        import re
        if not re.fullmatch(r"[A-Za-z0-9._+~^-]+", version):
            raise HTTPException(status_code=400, detail="First unaffected version contains unsupported characters")
        reason += f"\nFirst unaffected version: {version}"
    cve_id = payload.cve_id.upper()
    requester = actor_identity(request, role)
    with db.session() as conn:
        finding = db.get_finding_at(conn, cve_id, payload.branch, payload.spec_path)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        if db.pending_dispute(conn, cve_id, payload.branch, payload.spec_path):
            raise HTTPException(status_code=409, detail="A dispute for this package is already waiting for approval.")
        auto = "approve_dispute" in _CAPABILITIES.get(role, set())
        dispute = db.create_dispute(
            conn, finding, reason, requester,
            first_unaffected_version="" if payload.never_applicable else version,
            never_applicable=payload.never_applicable,
            status="approved" if auto else "pending",
        )
        applied = _apply_approved_dispute(conn, dispute) if auto else {}
    return {"dispute": dispute, "approved": auto, **applied}


@app.get("/api/disputes")
def get_disputes(
    status: str = "",
    search: str = "",
    page: int = 1,
    limit: int = Query(50, ge=1, le=200),
) -> dict:
    """Dispute requests, newest first, with how many are in each state."""
    if status and status not in db.DISPUTE_STATUSES:
        raise HTTPException(status_code=400, detail="status must be pending, approved or rejected")
    with db.session() as conn:
        rows, total = db.list_disputes(
            conn, status=status, search=search.strip(),
            limit=limit, offset=(max(page, 1) - 1) * limit,
        )
        counts = db.dispute_counts(conn)
    return {"items": rows, "total": total, "page": page, "limit": limit, "counts": counts}


class DisputeDecision(BaseModel):
    note: str = ""


def _decide_dispute(dispute_id: int, status: str, payload: DisputeDecision, request: Request) -> dict:
    role = require_capability(request, "approve_dispute", "approve or reject disputes")
    decider = actor_identity(request, role)
    with db.session() as conn:
        if not db.get_dispute(conn, dispute_id):
            raise HTTPException(status_code=404, detail="Dispute not found")
        dispute = db.decide_dispute(conn, dispute_id, status, decider, (payload.note or "").strip())
        if dispute is None:
            raise HTTPException(status_code=409, detail="This dispute has already been decided.")
        applied = _apply_approved_dispute(conn, dispute) if status == "approved" else {}
    return {"dispute": dispute, **applied}


@app.post("/api/disputes/{dispute_id}/approve")
def approve_dispute(dispute_id: int, request: Request, payload: DisputeDecision | None = None) -> dict:
    """Admin approval: the package is marked Disputed and the reason joins its history."""
    return _decide_dispute(dispute_id, "approved", payload or DisputeDecision(), request)


@app.post("/api/disputes/{dispute_id}/reject")
def reject_dispute(dispute_id: int, request: Request, payload: DisputeDecision | None = None) -> dict:
    """Admin rejection: nothing changes on the package; the note tells the requester why."""
    return _decide_dispute(dispute_id, "rejected", payload or DisputeDecision(), request)


@app.post("/api/triage/google-pr")
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
    identity = actor_identity(request, role)
    # A developer who sets the PR owns the follow-up; the automation identity keeps the admin as owner.
    owner = identity if role == ROLE_DEVELOPER else (config.ADMIN_EMAIL or config.ADMIN_IDENTITY)
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
            owner=owner,
        )
    if request.url.path.endswith("/google-pr"):
        # Backward-compatible response names for the original automation client.
        record = {
            **record,
            "google_pr_number": record.get("github_pr_number", ""),
            "google_pr_url": record.get("github_pr_url", ""),
            "google_pr_set_by": record.get("github_pr_set_by", ""),
            "google_pr_set_at": record.get("github_pr_set_at", ""),
        }
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


def require_claimer(request: Request) -> tuple[str, str]:
    """(role, email) of a signed-in developer or administrator; anyone else gets 401."""
    role = resolve_role(request)
    if "claim" not in _CAPABILITIES.get(role, set()):
        raise HTTPException(status_code=401, detail="Only developers and the administrator can claim or track CVEs.")
    return role, actor_identity(request, role).strip().lower()


@app.post("/api/triage/claim")
def claim_finding(payload: FindingRef, request: Request) -> dict:
    """Assign a package's CVE to the signed-in account. Developers and the administrator only."""
    role, me = require_claimer(request)
    cve_id = payload.cve_id.upper()
    with db.session() as conn:
        current = ((db.get_triage(conn, cve_id, payload.branch, payload.spec_path) or {}).get("owner") or "").strip()
        if current and current.lower() != me and role != ROLE_ADMIN:
            raise HTTPException(status_code=409, detail=f"Already claimed by {current}.")
        record = db.upsert_triage(conn, cve_id, payload.branch, payload.spec_path, owner=me)
    return {"triage": record}


@app.post("/api/triage/release")
def release_finding(payload: FindingRef, request: Request) -> dict:
    """Give a claimed package back. Only its owner, or the administrator, can."""
    role, me = require_claimer(request)
    cve_id = payload.cve_id.upper()
    with db.session() as conn:
        current = ((db.get_triage(conn, cve_id, payload.branch, payload.spec_path) or {}).get("owner") or "").strip()
        if current and current.lower() != me and role != ROLE_ADMIN:
            raise HTTPException(status_code=409, detail=f"Claimed by {current}; only they or the administrator can release it.")
        record = db.upsert_triage(conn, cve_id, payload.branch, payload.spec_path, owner="")
    return {"triage": record}


@app.get("/api/workflows")
def get_workflows(request: Request) -> dict:
    """Every developer's packages, grouped by owner. Developers and the administrator only.

    A package belongs to whoever the administrator assigned it to, otherwise to whoever
    claimed it (the same rule the CVE pages use). The signed-in account is always the
    first group, even when empty; the other owners follow in alphabetical order.
    """
    _, me = require_claimer(request)
    with db.session() as conn:
        rows, _ = db.list_findings(conn, limit=1_000_000, offset=0)
        _decorate_findings(conn, rows, slim=True)
    groups: dict[str, list[dict]] = {me: []}
    for row in rows:
        assigned = ((row.get("assignment") or {}).get("assignee_email") or "").strip().lower()
        claimed = ((row.get("triage") or {}).get("owner") or "").strip().lower()
        owner = assigned or claimed
        if not owner:
            continue
        row["held_via"] = "assigned" if assigned else "claimed"
        groups.setdefault(owner, []).append(row)
    ordered = [me] + sorted(email for email in groups if email != me)
    return {
        "me": me,
        "owner": me,
        "total": sum(len(items) for items in groups.values()),
        "groups": [{"owner": email, "total": len(groups[email]), "items": groups[email]} for email in ordered],
    }


@app.post("/api/cves/{cve_id}/rescore")
def rescore_cve(cve_id: str, payload: RescoreRequest, request: Request) -> dict:
    """Admin-only: replace a CVE's severity and CVSS score, with a reason."""
    role = require_admin(request)
    cve_id = cve_id.upper()
    severity = payload.severity.strip().lower()
    if severity not in ("critical", "high", "medium", "low", "none"):
        raise HTTPException(status_code=400, detail="Severity must be critical, high, medium, low or none")
    score = payload.cvss_score
    if score is not None and not 0 <= score <= 10:
        raise HTTPException(status_code=400, detail="CVSS score must be between 0 and 10")
    reason = payload.reason.strip()
    if not reason:
        raise HTTPException(status_code=400, detail="A rescore needs a reason")
    with db.session() as conn:
        if not db.findings_for_cve(conn, cve_id):
            raise HTTPException(status_code=404, detail="CVE not found in the current scan")
        record = db.set_rescore(conn, cve_id, severity, score, reason, actor_identity(request, role))
    return {"rescore": record}


# -- assignment queue -------------------------------------------------------
@app.get("/api/assignments")
def get_assignments() -> dict:
    with db.session() as conn:
        return {"items": db.list_assignments(conn)}


@app.post("/api/assignments")
def create_assignment(payload: AssignmentRequest, request: Request) -> dict:
    require_admin(request)
    target = payload.target_repo or config.PATCH_TARGET_REPO
    assignee = payload.assignee_email.strip().lower()
    if assignee and assignee not in ASSIGNABLE_EMAILS:
        raise HTTPException(status_code=400, detail="Choose an assignee from the configured demo assignment list.")
    with db.session() as conn:
        finding = db.get_finding(
            conn, payload.cve_id.upper(), payload.package_name, spec_path=payload.spec_path
        )
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        record = db.create_assignment(
            conn, payload.cve_id.upper(), payload.package_name, target, payload.notes, assignee
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
    requested_branches = payload.branches or ["3.0", "4.0"]
    allowed_branches = {"3.0", "4.0"}
    invalid_branches = sorted(set(requested_branches) - allowed_branches)
    if invalid_branches:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported branch(es): {', '.join(invalid_branches)}. Choose a branch from azurelinux-test.",
        )
    # Use the advisory ecosystem matching the selected release family. The
    # package/spec inventory itself always comes from the configured azurelinux-test fork.
    if all(b == "4.0" for b in requested_branches):
        ecosystem = "Azure Linux:4"
    elif all(b == "3.0" for b in requested_branches):
        ecosystem = "Azure Linux:3"
    else:
        ecosystem = "Azure Linux:3+Azure Linux:4"
    options = ScanOptions(
        branches=requested_branches,
        ecosystem=ecosystem,
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
