"""Capture dashboard screenshots for the README.

Boots the FastAPI app on a throwaway port inside this process, renders a handful
of dashboard routes with a headless Chromium, and writes PNGs to
``docs/screenshots/``. Requires the optional ``playwright`` dev dependency::

    pip install playwright && python -m playwright install chromium
    python scripts/screenshots.py

This is a documentation helper only; it is never used by the scanner or the API.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import uvicorn  # noqa: E402

from vulnex import db  # noqa: E402
from vulnex.api import app  # noqa: E402

OUT_DIR = ROOT / "docs" / "screenshots"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_up(port: int, timeout: float = 30.0) -> None:
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2)
            return
        except Exception:
            time.sleep(0.3)
    raise RuntimeError("server did not become ready")


def _pick_cve() -> str:
    with db.session() as conn:
        row = conn.execute(
            "SELECT cve_id FROM findings WHERE severity IN ('critical','high') "
            "AND status = 'affected' ORDER BY confidence DESC LIMIT 1"
        ).fetchone()
    return row["cve_id"] if row else "CVE-2026-19931"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    _wait_up(port)
    base = f"http://127.0.0.1:{port}"

    from playwright.sync_api import sync_playwright

    shots = [
        ("dashboard", "#/", 2200),
        ("affected", "#/affected", 1800),
        ("patched", "#/patched", 1500),
        ("packages", "#/packages", 1500),
        ("cve-detail", f"#/cve/{_pick_cve()}", 2600),
        ("methodology", "#/about", 1200),
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        for name, route, settle in shots:
            page.goto(base + "/", wait_until="load")
            page.evaluate(f"location.hash = {route!r}")
            page.wait_for_timeout(settle)
            target = OUT_DIR / f"{name}.jpg"
            page.screenshot(path=str(target), full_page=True, type="jpeg", quality=80)
            print(f"wrote {target.relative_to(ROOT)}")
        browser.close()

    server.should_exit = True
    thread.join(timeout=10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
