"""
Primary CLI entry point for Linux Server Audit (serveraudit / nodeaudit).
"""

from __future__ import annotations
import argparse
from pathlib import Path
import sys

from .. import __version__
from .audit import AuditOrchestrator
from .diff import run_diff
from .render import run_render
from ..core.snapshot import SnapshotManager

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="serveraudit",
        description="Comprehensive Open-Source Linux Server Auditing, Documentation, Topology and Baselining Platform",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Command: audit
    audit_parser = subparsers.add_parser("audit", help="Run a server audit")
    audit_parser.add_argument("--profile", choices=["private", "public"], default="private", help="Audit profile (default: private)")
    audit_parser.add_argument("--output-dir", default="audits", help="Directory to store audit bundles (default: audits)")
    audit_parser.add_argument("--format", default="markdown,json,html", help="Comma-separated formats: markdown,json,html,pdf")
    audit_parser.add_argument("--config", default=None, help="Custom configuration YAML file")
    audit_parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (minimal terminal output)")

    # Command: diff
    diff_parser = subparsers.add_parser("diff", help="Compare two snapshots and detect configuration drift")
    diff_parser.add_argument("snapshot_a", help="Path or directory name of first snapshot")
    diff_parser.add_argument("snapshot_b", help="Path or directory name of second snapshot")
    diff_parser.add_argument("--base-dir", default="audits", help="Base directory of snapshots (default: audits)")

    # Command: render
    render_parser = subparsers.add_parser("render", help="Re-render an existing audit.json snapshot")
    render_parser.add_argument("json_file", help="Path to audit.json")
    render_parser.add_argument("--format", choices=["markdown", "html", "pdf"], default="markdown", help="Output format")
    render_parser.add_argument("-o", "--output", default=None, help="Output file path (default: stdout for markdown/html)")

    # Command: list
    list_parser = subparsers.add_parser("list", help="List past audit snapshots")
    list_parser.add_argument("--output-dir", default="audits", help="Base directory of snapshots")

    # Command: verify
    verify_parser = subparsers.add_parser("verify", help="Verify cryptographic integrity of an audit bundle")
    verify_parser.add_argument("snapshot_dir", help="Path to snapshot directory")

    # Command: web
    web_parser = subparsers.add_parser("web", help="Start self-hosted web interface")
    web_parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    web_parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    web_parser.add_argument("--output-dir", default="audits", help="Base directory of snapshots")

    # Default to 'audit' if no arguments provided
    args = parser.parse_args()
    if args.command is None:
        orchestrator = AuditOrchestrator()
        orchestrator.run_audit()
        return 0

    if args.command == "audit":
        formats = [f.strip() for f in args.format.split(",") if f.strip()]
        orchestrator = AuditOrchestrator(
            profile=args.profile,
            output_dir=args.output_dir,
            formats=formats,
            config_file=args.config,
            quiet=args.quiet,
        )
        orchestrator.run_audit()
        return 0

    elif args.command == "diff":
        return run_diff(args.snapshot_a, args.snapshot_b, base_dir=args.base_dir)

    elif args.command == "render":
        return run_render(args.json_file, output_format=args.format, output_file=args.output)

    elif args.command == "list":
        sm = SnapshotManager(args.output_dir)
        snapshots = sm.list_snapshots()
        if not snapshots:
            print(f"No audit snapshots found in '{args.output_dir}'. Run 'serveraudit audit' to create one.")
            return 0
        print("======================================================================")
        print(" HISTORICAL AUDIT SNAPSHOTS")
        print("======================================================================")
        for s in snapshots:
            print(f"• {s['name']}")
            print(f"    Hostname:  {s['hostname']}")
            print(f"    Timestamp: {s['timestamp']}")
            print(f"    Profile:   {s['profile']}")
            print(f"    Artifacts: MD={'✓' if s['has_md'] else '✗'}, JSON=✓, HTML={'✓' if s['has_html'] else '✗'}, PDF={'✓' if s['has_pdf'] else '✗'}")
            print(f"    Location:  {s['path']}\n")
        return 0

    elif args.command == "verify":
        sm = SnapshotManager()
        valid, issues = sm.verify_integrity(Path(args.snapshot_dir))
        if valid:
            print(f"✓ Snapshot '{args.snapshot_dir}' integrity VERIFIED (All SHA256 hashes match).")
            return 0
        else:
            print(f"✗ Snapshot '{args.snapshot_dir}' integrity FAILED:")
            for issue in issues:
                print(f"  - {issue}")
            return 1

    elif args.command == "web":
        from ..web.app import run_web_server
        run_web_server(host=args.host, port=args.port, base_dir=args.output_dir)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
