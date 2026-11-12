"""Command-line bridge between the .NET API and the Python scan/enrichment engine.

The web API is written in .NET; the scanner, CVE enrichment, fixed-CVE ledger and the
VulnerabilityData feed reader stay in Python. The API starts this module as a
subprocess and reads JSON from its standard output::

    python -m vulnex.engine_bridge migrate
    python -m vulnex.engine_bridge enrich CVE-2024-0001
    python -m vulnex.engine_bridge fixed-cves 3.0
    python -m vulnex.engine_bridge vuln-summary [--refresh]
    python -m vulnex.engine_bridge vuln-packages [--refresh]
    python -m vulnex.engine_bridge vuln-package NAME [--refresh]
    python -m vulnex.engine_bridge scan --options '{"branches": ["3.0"], ...}'

Exit codes: 0 ok, 3 feed error (the API answers 502), 1 anything else. A failure always
prints ``{"error": "..."}`` first. ``scan`` streams one JSON object per line
(``progress`` lines, then a final ``result`` or ``error`` line).

It reads the same environment variables as before (``DATABASE_URL`` and friends).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def _emit(payload: Any) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    sys.stdout.flush()


def _migrate() -> int:
    from . import config, db

    seeded: Any = None
    if config.DATABASE_URL:
        db.migrate_postgres()
        seeded = _seed_snapshot()
    _emit({"ok": True, "seeded": seeded})
    return 0


def _seed_snapshot() -> Any:
    """On a brand-new Postgres, load the bundled snapshot (data/vulnex.db) once.

    The old Python API did this on startup. A database that already has scans is left
    alone, and triage tables are never overwritten. Missing first-scanned dates are
    filled from the snapshot. Set VULNEX_SEED_SNAPSHOT=0 to skip (tests).
    """
    import os

    from . import config, db
    from .sqlite_import import backfill_first_seen, seed_if_empty

    if os.environ.get("VULNEX_SEED_SNAPSHOT", "1") == "0":
        return None
    conn = db.connect()
    try:
        result = seed_if_empty(conn, config.DB_PATH)
        backfill_first_seen(conn, config.DB_PATH)
        return {"seeded": bool(result.get("seeded")), "reason": result.get("reason", "")}
    except Exception as exc:  # a bad snapshot must never stop the service
        try:
            conn.rollback()
        except Exception:
            pass
        sys.stderr.write(f"[vulnex] could not load the bundled snapshot: {exc}\n")
        return {"seeded": False, "reason": str(exc)}
    finally:
        conn.close()


def _enrich(cve_id: str) -> int:
    from .enrichment import enrich_cve

    _emit(enrich_cve(cve_id.upper()))
    return 0


def _fixed_cves(branch: str) -> int:
    from . import db, fixed_cves

    conn = db.connect()
    try:
        _emit(fixed_cves.build_ledger(conn, branch))
    finally:
        conn.close()
    return 0


def _vuln(command: str, name: str | None, refresh: bool) -> int:
    from .sources.vulnerabilitydata import FeedError, VulnerabilityDataSource

    source = VulnerabilityDataSource()
    try:
        if command == "vuln-summary":
            _emit(source.summary(refresh=refresh))
        elif command == "vuln-packages":
            _emit(source.packages(refresh=refresh))
        else:
            _emit(source.package(name or "", refresh=refresh))
    except FeedError as exc:
        _emit({"error": str(exc)})
        return 3
    return 0


def _scan(options_json: str) -> int:
    from . import db
    from .scanner import ScanOptions, run_scan

    raw = json.loads(options_json or "{}")
    options = ScanOptions(
        branches=raw.get("branches") or ["3.0", "4.0"],
        ecosystem=raw.get("ecosystem") or ScanOptions().ecosystem,
        packages=set(raw["packages"]) if raw.get("packages") else None,
        limit=int(raw.get("limit") or 0),
        verify_blobs=bool(raw.get("verify_blobs", True)),
        enrich=bool(raw.get("enrich", True)),
    )
    conn = db.connect()
    try:
        db.init_db(conn)

        def progress(message: str, **_extra: Any) -> None:
            _emit({"type": "progress", "message": message})

        result = run_scan(conn, options, progress=progress)
        _emit({"type": "result", "result": result})
        return 0
    except Exception as exc:  # reported to the API, which keeps serving
        _emit({"type": "error", "error": str(exc)})
        return 1
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnex.engine_bridge")
    parser.add_argument(
        "command",
        choices=["migrate", "enrich", "fixed-cves", "vuln-summary", "vuln-packages", "vuln-package", "scan"],
    )
    parser.add_argument("arg", nargs="?", default="")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--options", default="{}")
    args = parser.parse_args(argv)
    try:
        if args.command == "migrate":
            return _migrate()
        if args.command == "enrich":
            return _enrich(args.arg)
        if args.command == "fixed-cves":
            return _fixed_cves(args.arg or "3.0")
        if args.command == "scan":
            return _scan(args.options)
        return _vuln(args.command, args.arg, args.refresh)
    except Exception as exc:
        _emit({"error": str(exc)})
        return 1


if __name__ == "__main__":
    sys.exit(main())
