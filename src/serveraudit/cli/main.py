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
    audit_parser.add_argument(
        "--mode",
        choices=["user", "sudo"],
        default=None,
        help="Audit execution mode: 'user' (unprivileged, zero sudo) or 'sudo' (elevated checks)",
    )
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
    if args.command is None or args.command == "audit":
        from ..core.privileges import AuditMode, PrivilegeManager
        from ..core.executor import CommandExecutor
        import os

        # 1. Determine AuditMode
        raw_mode = getattr(args, "mode", None)
        if raw_mode:
            selected_mode = AuditMode.SUDO if raw_mode.lower() == "sudo" else AuditMode.USER
        else:
            # When --mode is omitted:
            # If stdin is a TTY, prompt the user
            # If stdin is non-interactive, default deterministically to USER mode
            if sys.stdin.isatty():
                try:
                    print("Select audit execution mode:")
                    print("  [1] user - unprivileged audit (hard guarantee: zero sudo invocations)")
                    print("  [2] sudo - elevated audit (validates sudo once at startup)")
                    choice = input("Enter choice [1/2] (default: 1): ").strip()
                    selected_mode = AuditMode.SUDO if choice == "2" else AuditMode.USER
                except (EOFError, KeyboardInterrupt):
                    print("\nAudit aborted.")
                    return 130
            else:
                selected_mode = AuditMode.USER

        # 2. Invariant check: os.geteuid() == 0 and mode == USER
        if hasattr(os, "geteuid") and os.geteuid() == 0 and selected_mode == AuditMode.USER:
            sys.stderr.write(
                "Error: AuditMode.USER cannot be run as root (EUID 0). "
                "User mode must be executed as a non-root user. "
                "To audit as root or with elevated privileges, run in sudo mode: 'serveraudit audit --mode sudo'.\n"
            )
            return 1

        # 3. Construct mode-aware PrivilegeManager
        priv_mgr = PrivilegeManager(mode=selected_mode)

        # 4. If SUDO mode and EUID != 0, run interactive sudo -v once
        if selected_mode == AuditMode.SUDO:
            if not priv_mgr.is_root:
                valid = priv_mgr.validate_sudo()
                if not valid:
                    sys.stderr.write(
                        "Warning: Sudo validation failed or was cancelled. "
                        "Privileged collection will be unavailable; REQUIRED collectors will be skipped.\n"
                    )

        # 5. Construct mode-aware CommandExecutor
        executor = CommandExecutor(privilege_manager=priv_mgr, mode=selected_mode)

        # 6. Run orchestrator
        profile = getattr(args, "profile", "private")
        output_dir = getattr(args, "output_dir", "audits")
        format_arg = getattr(args, "format", "markdown,json,html")
        formats = [f.strip() for f in format_arg.split(",") if f.strip()]
        config_file = getattr(args, "config", None)
        quiet = getattr(args, "quiet", False)

        orchestrator = AuditOrchestrator(
            mode=selected_mode,
            profile=profile,
            output_dir=output_dir,
            formats=formats,
            config_file=config_file,
            quiet=quiet,
            privilege_manager=priv_mgr,
            executor=executor,
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
