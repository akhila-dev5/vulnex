"""VULNEX command line interface.

Examples::

    python -m vulnex.cli scan --branches 3.0 or 4.0
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
    if not branches or set(branches) - {"3.0", "4.0"}:
        print("[vulnex] Scan only stable branches 3.0 and/or 4.0.", file=sys.stderr)
        return 2
    packages = {p.strip() for p in args.packages.split(",") if p.strip()} if args.packages else None
    options = ScanOptions(
        branches=branches,
        packages=packages,
        limit=args.limit,
        ecosystem=args.ecosystem or (
            "Azure Linux:4" if branches == ["4.0"] else "Azure Linux:3" if branches == ["3.0"] else "Azure Linux:3+Azure Linux:4"
        ),
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


def _cmd_vuln_data(args: argparse.Namespace) -> int:
    """Show the pre-computed NVD inventory published by VulnerabilityData."""
    from .sources.vulnerabilitydata import FeedError, VulnerabilityDataSource

    source = VulnerabilityDataSource()
    try:
        if args.package:
            pkg = source.package(args.package, refresh=args.refresh)
            if pkg is None:
                print(
                    f"[vulnex] package not in the VulnerabilityData feed: {args.package}",
                    file=sys.stderr,
                )
                return 1
            print(json.dumps(pkg, indent=2))
        else:
            print(json.dumps(source.summary(refresh=args.refresh), indent=2))
    except FeedError as exc:
        print(f"[vulnex] {exc}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnex", description="Vulnex Azure Linux CVE scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_scan(p: argparse.ArgumentParser) -> None:
        p.add_argument("--branches", default="3.0", help="Stable release branch(es) to scan: 3.0, 4.0, or 3.0,4.0")
        p.add_argument("--packages", default="", help="Comma-separated package allow-list")
        p.add_argument("--limit", type=int, default=0, help="Max specs to scan (0 = all)")
        p.add_argument("--ecosystem", default=None, help="Override advisory ecosystem; inferred from selected branch by default")
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

    vuln_data = sub.add_parser(
        "vuln-data",
        help="Show the NVD inventory published by the VulnerabilityData repo",
    )
    vuln_data.add_argument(
        "--package",
        default="",
        help="Print one package's CVE inventory instead of the feed summary",
    )
    vuln_data.add_argument(
        "--refresh",
        action="store_true",
        help="Re-fetch the feed instead of using the on-disk cache",
    )
    vuln_data.set_defaults(func=_cmd_vuln_data)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
