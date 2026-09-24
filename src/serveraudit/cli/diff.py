"""
CLI command for comparing two historical snapshots and detecting configuration drift.
"""

from __future__ import annotations
from pathlib import Path
import sys
from typing import Any, Dict

from ..analysis.drift import compare_snapshots
from ..core.snapshot import SnapshotManager


def run_diff(snapshot_a_path: str, snapshot_b_path: str, base_dir: str = "audits") -> int:
    """Loads two snapshots and prints the drift report."""
    sm = SnapshotManager(base_dir)

    data_a = sm.load_snapshot(snapshot_a_path)
    if not data_a:
        print(f"Error: Snapshot A not found at '{snapshot_a_path}'", file=sys.stderr)
        return 1

    data_b = sm.load_snapshot(snapshot_b_path)
    if not data_b:
        print(f"Error: Snapshot B not found at '{snapshot_b_path}'", file=sys.stderr)
        return 1

    drift = compare_snapshots(data_a, data_b)

    meta_a = drift.get("metadata_a", {})
    meta_b = drift.get("metadata_b", {})

    print("======================================================================")
    print(" SERVER CONFIGURATION DRIFT REPORT")
    print("======================================================================")
    print(f"Snapshot A: {meta_a.get('hostname')} ({meta_a.get('timestamp')})")
    print(f"Snapshot B: {meta_b.get('hostname')} ({meta_b.get('timestamp')})")
    print("----------------------------------------------------------------------")

    if not drift.get("has_drift"):
        print("✓ No configuration drift detected between these snapshots.")
        print("======================================================================")
        return 0

    for category, changes in drift.get("categories", {}).items():
        print(f"\n[{category}]")
        if isinstance(changes, list):
            for ch in changes:
                if isinstance(ch, dict):
                    if "old" in ch and "new" in ch:
                        print(f"  - {ch.get('item', 'Item')}:")
                        print(f"      Old: {ch.get('old')}")
                        print(f"      New: {ch.get('new')}")
        elif isinstance(changes, dict):
            if "added" in changes and changes["added"]:
                print(f"  + Added: {', '.join(changes['added'])}")
            if "removed" in changes and changes["removed"]:
                print(f"  - Removed: {', '.join(changes['removed'])}")
            if "opened" in changes and changes["opened"]:
                print(f"  + Newly Opened Ports: {', '.join(changes['opened'])}")
            if "closed" in changes and changes["closed"]:
                print(f"  - Closed Ports: {', '.join(changes['closed'])}")
            if "installed_count_delta" in changes:
                delta = changes["installed_count_delta"]
                print(f"  * Installed Packages Delta: {'+' if delta > 0 else ''}{delta} ({changes.get('old_count')} -> {changes.get('new_count')})")
            if "changed" in changes and changes["changed"]:
                for c in changes["changed"]:
                    print(f"  * Changed {c.get('container')}: {c.get('old')} -> {c.get('new')}")

    print("\n======================================================================")
    return 0
