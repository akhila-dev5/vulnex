"""Static export for GitHub Pages.

Produces a self-contained copy of the dashboard plus pre-baked JSON under
``<out>/api/`` so the SPA can run with no backend at all. ``app.js`` detects the
``window.VULNEX_STATIC`` flag and answers every ``/api`` call from the bundled
snapshot (client-side filtering, sorting and pagination).

This keeps the whole project on free infrastructure: GitHub Actions runs the
scan, this export turns the SQLite snapshot into static files, and GitHub Pages
serves them.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from . import config, db

__all__ = ["export_site", "default_out_dir"]

# The public export is always the read-only tier: there is no backend behind it,
# and the baked role keeps every editor-only control out of the UI.
_STATIC_INJECT = (
    '    <script>window.VULNEX_STATIC = { base: "./", generated: "%(generated)s", '
    'role: "viewer", write_enabled: false };</script>\n'
    '    <div class="static-banner" role="note"><b>Read-only showcase</b> — a static '
    'snapshot of this VULNEX scan. Queuing work and triage comments need editor access; '
    'search, sorting and paging all run in your browser.</div>\n'
)

# Keep the payload lean: trim long free-text fields that are not rendered in full.
_DESC_LIMIT = 600


def default_out_dir() -> Path:
    return config.PROJECT_ROOT / "site"


def _write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _trim_finding(f: dict) -> dict:
    if f.get("description") and len(f["description"]) > _DESC_LIMIT:
        f["description"] = f["description"][:_DESC_LIMIT]
    return f


def export_site(
    out_dir: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
    frontend_dir: str | Path | None = None,
) -> dict:
    """Write the static dashboard + JSON snapshot and return a small summary."""
    out = Path(out_dir or default_out_dir())
    frontend = Path(frontend_dir or config.FRONTEND_DIR)
    out.mkdir(parents=True, exist_ok=True)

    # 1. Static assets.
    for asset in ("styles.css", "app.js"):
        shutil.copyfile(frontend / asset, out / asset)
    html = (frontend / "index.html").read_text(encoding="utf-8")
    generated = db.utcnow()
    html = html.replace(
        "  <body>\n",
        "  <body>\n" + (_STATIC_INJECT % {"generated": generated}),
        1,
    )
    (out / "index.html").write_text(html, encoding="utf-8")
    # A copy of index.html for 404-style deep links on GitHub Pages.
    shutil.copyfile(out / "index.html", out / "404.html")

    # 2. JSON snapshot.
    conn = db.connect(db_path)
    try:
        stats = db.stats(conn)
        stats["repository"] = config.repository_metadata()
        findings, _ = db.list_findings(conn, limit=1_000_000)
        packages, _ = db.list_packages(conn, limit=1_000_000)
        patches = [
            dict(r) for r in conn.execute("SELECT * FROM patches ORDER BY id").fetchall()
        ]
        for p in patches:
            p["cve_ids"] = db.loads(p.get("cve_ids"), [])
        history = db.scan_history(conn, limit=25)

        from .api import methodology as methodology_payload

        api_dir = out / "api"
        _write(api_dir / "stats.json", stats)
        _write(api_dir / "methodology.json", methodology_payload())
        _write(api_dir / "findings.json", [_trim_finding(f) for f in findings])
        _write(api_dir / "packages.json", packages)
        _write(api_dir / "patches.json", patches)
        _write(
            api_dir / "scans.json",
            {
                "latest": history[0] if history else None,
                "items": history,
                "manager": {
                    "running": False,
                    "stage": "static snapshot",
                    "started_at": None,
                    "finished_at": None,
                    "log": [],
                    "result": None,
                    "error": None,
                },
            },
        )
    finally:
        conn.close()

    return {
        "out_dir": str(out),
        "generated": generated,
        "findings": len(findings),
        "packages": len(packages),
        "patches": len(patches),
    }
