"""Capture the screenshots used in the docs.

Start the app first (``make serve``, or any running Vulnex URL), then::

    pip install playwright && python -m playwright install chromium
    python scripts/screenshots.py [http://localhost:8000]

Writes PNGs to ``docs/images/``. A documentation helper only; the scanner and the
API never use it.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs" / "images"
BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")


def _pick_cve() -> str:
    """A CVE that touches several packages, so the CVE page has something to show."""
    url = f"{BASE}/api/findings?severity=critical&limit=300"
    items = json.load(urllib.request.urlopen(url, timeout=30))["items"]
    counts: dict[str, int] = {}
    for item in items:
        counts[item["cve_id"]] = counts.get(item["cve_id"], 0) + 1
    return max(counts, key=lambda cve: counts[cve]) if counts else "CVE-2024-0001"


def main() -> int:
    from playwright.sync_api import sync_playwright

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for old in OUT_DIR.glob("*.png"):
        old.unlink()
    cve = _pick_cve()
    shots = [
        ("cves", "#/", "CVE list with the filter sidebar"),
        ("packages", "#/packages", "Package list"),
        ("cve-detail", f"#/cve/{cve}", f"{cve} and every package it affects"),
    ]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        for name, route, label in shots:
            page.goto(f"{BASE}/{route}")
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(800)
            page.screenshot(path=str(OUT_DIR / f"{name}.png"), full_page=False)
            print(f"{name}.png  {label}")
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
