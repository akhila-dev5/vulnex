"""VULNEX command line interface.

Examples::

    python -m vulnex.cli scan --branches 3.0-dev,fasttrack/3.0
    python -m vulnex.cli scan --packages curl,openssl,sqlite --no-blobs
    python -m vulnex.cli stats
    python -m vulnex.cli serve --port 8000
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import config, db
from .export import default_out_dir, export_site
from .scanner import ScanOptions, run_scan


def _cmd_scan(args: argparse.Namespace) -> int:
    branches = [b.strip() for b in args.branches.split(",") if b.strip()]
    packages = {p.strip() for p in args.packages.split(",") if p.strip()} if args.packages else None
    options = ScanOptions(
        branches=branches,
        packages=packages,
        limit=args.limit,
        ecosystem=args.ecosystem,
        include_extended=args.include_extended,
        verify_blobs=not args.no_blobs,
        corroborate=not args.no_corroborate,
        enrich=not args.no_enrich,
        enrich_limit=args.enrich_limit,
        owner=args.owner,
        repo=args.repo,
    )

    conn = db.connect(args.db)
    db.init_db(conn)

    def progress(message: str, **extra) -> None:
        print(f"[vulnex] {message}", flush=True)

    try:
        result = run_scan(conn, options, progress=progress)
    except Exception as exc:
        print(f"[vulnex] scan failed: {exc}", file=sys.stderr)
        return 1
    counts = result["counts"]
    print(json.dumps(result, indent=2))
    print(
        f"[vulnex] done in {result['duration_seconds']}s — "
        f"{counts['packages']} packages, {counts['findings']} findings "
        f"(affected {counts['affected']}, patched {counts['patched']}, "
        f"false-positive {counts['false_positive']}, unconfirmed {counts['unconfirmed']})",
        flush=True,
    )
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    with db.session(args.db) as conn:
        print(json.dumps(db.stats(conn), indent=2, default=str))
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    summary = export_site(args.out or default_out_dir(), db_path=args.db)
    print(json.dumps(summary, indent=2))
    print(f"[vulnex] static site written to {summary['out_dir']}", flush=True)
    return 0


def _cmd_hash_password(args: argparse.Namespace) -> int:
    """Print a PBKDF2 hash to put in VULNEX_ADMIN_PASSWORD_HASH."""
    import getpass

    from . import auth

    password = args.password or getpass.getpass("Admin password: ")
    if args.password and not args.password.strip():
        print("[vulnex] refusing an empty password", file=sys.stderr)
        return 2
    print(auth.hash_password(password))
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    if args.db:
        config.DB_PATH = Path(args.db)
    uvicorn.run(
        "vulnex.api:app",
        host=args.host,
        port=args.port,
        reload=False,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnex", description="Azure Linux CVE scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_scan(p: argparse.ArgumentParser) -> None:
        p.add_argument("--branches", default=",".join(config.DEFAULT_BRANCHES))
        p.add_argument("--packages", default="", help="Comma-separated package allow-list")
        p.add_argument("--limit", type=int, default=0, help="Max specs to scan (0 = all)")
        p.add_argument("--ecosystem", default=config.OSV_ECOSYSTEM)
        p.add_argument("--owner", default=None)
        p.add_argument("--repo", default=None)
        p.add_argument("--db", default=None)
        p.add_argument("--enrich-limit", type=int, default=400)
        p.add_argument("--include-extended", action="store_true")
        p.add_argument("--no-blobs", action="store_true")
        p.add_argument("--no-corroborate", action="store_true")
        p.add_argument("--no-enrich", action="store_true")

    scan = sub.add_parser("scan", help="Run a scan and update the snapshot")
    add_scan(scan)
    scan.set_defaults(func=_cmd_scan)

    stats = sub.add_parser("stats", help="Print dashboard stats")
    stats.add_argument("--db", default=None)
    stats.set_defaults(func=_cmd_stats)

    export = sub.add_parser(
        "export", help="Write a static JSON snapshot + dashboard for GitHub Pages"
    )
    export.add_argument("--out", default=None, help="Output directory (default: site/)")
    export.add_argument("--db", default=None)
    export.set_defaults(func=_cmd_export)

    serve = sub.add_parser("serve", help="Serve the dashboard API")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--db", default=None)
    serve.set_defaults(func=_cmd_serve)

    hashpw = sub.add_parser(
        "hash-password",
        help="Hash the admin password for VULNEX_ADMIN_PASSWORD_HASH",
    )
    hashpw.add_argument(
        "--password",
        default="",
        help="Password to hash (omit to be prompted, so it stays out of shell history)",
    )
    hashpw.set_defaults(func=_cmd_hash_password)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
