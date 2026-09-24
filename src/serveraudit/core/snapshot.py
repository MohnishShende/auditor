"""
Audit bundle persistence, snapshot management, and SHA256 integrity verification.
"""

from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple


class SnapshotManager:
    """Handles snapshot directory creation, artifact saving, and integrity verification."""

    def __init__(self, base_directory: str | Path = "audits") -> None:
        self.base_dir = Path(base_directory)

    def create_snapshot_dir(self, hostname: str, timestamp_str: str) -> Path:
        """Create timestamped snapshot folder (e.g. audits/nodezero-2026-09-24T101700)."""
        # Sanitize timestamp for folder naming
        clean_ts = re.sub(r"[:+]", "", timestamp_str).replace("Z", "")
        clean_hostname = re.sub(r"[^a-zA-Z0-9_-]", "-", hostname)
        dir_name = f"{clean_hostname}-{clean_ts}"
        snapshot_path = self.base_dir / dir_name
        snapshot_path.mkdir(parents=True, exist_ok=True)
        return snapshot_path

    @staticmethod
    def calculate_sha256(filepath: Path) -> str:
        """Computes SHA256 hash of a file."""
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def save_bundle(
        self,
        snapshot_dir: Path,
        audit_json: Dict[str, Any],
        audit_md: str,
        manifest_json: Dict[str, Any],
        audit_html: Optional[str] = None,
        audit_pdf_bytes: Optional[bytes] = None,
    ) -> Dict[str, str]:
        """Saves all generated artifacts and calculates checksums."""
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        json_path = snapshot_dir / "audit.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(audit_json, f, indent=2, ensure_ascii=False)

        md_path = snapshot_dir / "audit.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(audit_md)

        manifest_path = snapshot_dir / "manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_json, f, indent=2, ensure_ascii=False)

        generated_files = [json_path, md_path, manifest_path]

        if audit_html:
            html_path = snapshot_dir / "audit.html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(audit_html)
            generated_files.append(html_path)

        if audit_pdf_bytes:
            pdf_path = snapshot_dir / "audit.pdf"
            with open(pdf_path, "wb") as f:
                f.write(audit_pdf_bytes)
            generated_files.append(pdf_path)

        # Compute checksums
        checksums: Dict[str, str] = {}
        checksum_lines = []
        for file in generated_files:
            file_hash = self.calculate_sha256(file)
            checksums[file.name] = file_hash
            checksum_lines.append(f"{file_hash}  {file.name}\n")

        checksums_path = snapshot_dir / "checksums.sha256"
        with open(checksums_path, "w", encoding="utf-8") as f:
            f.writelines(checksum_lines)

        return checksums

    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List all discovered snapshots in base directory."""
        if not self.base_dir.exists():
            return []

        snapshots = []
        for item in sorted(self.base_dir.iterdir(), reverse=True):
            if item.is_dir() and (item / "audit.json").exists():
                json_path = item / "audit.json"
                try:
                    with open(json_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    metadata = data.get("metadata", {})
                    snapshots.append({
                        "path": str(item),
                        "name": item.name,
                        "hostname": metadata.get("hostname", "unknown"),
                        "timestamp": metadata.get("timestamp", "unknown"),
                        "profile": metadata.get("profile", "unknown"),
                        "has_md": (item / "audit.md").exists(),
                        "has_json": True,
                        "has_html": (item / "audit.html").exists(),
                        "has_pdf": (item / "audit.pdf").exists(),
                    })
                except Exception:
                    continue
        return snapshots

    def load_snapshot(self, path_or_name: str | Path) -> Optional[Dict[str, Any]]:
        """Loads canonical audit.json from a path or directory name."""
        target = Path(path_or_name)
        if not target.exists():
            target = self.base_dir / path_or_name
        if target.is_dir():
            target = target / "audit.json"
        if not target.exists():
            return None

        with open(target, "r", encoding="utf-8") as f:
            return json.load(f)

    def verify_integrity(self, snapshot_dir: Path) -> Tuple[bool, List[str]]:
        """Verifies files against checksums.sha256."""
        checksum_file = snapshot_dir / "checksums.sha256"
        if not checksum_file.exists():
            return False, ["Missing checksums.sha256"]

        issues = []
        with open(checksum_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) != 2:
                    continue
                expected_hash, fname = parts
                fname = fname.lstrip("* ")
                fpath = snapshot_dir / fname
                if not fpath.exists():
                    issues.append(f"Missing file: {fname}")
                    continue
                actual_hash = self.calculate_sha256(fpath)
                if actual_hash.lower() != expected_hash.lower():
                    issues.append(f"Checksum mismatch for {fname}: expected {expected_hash}, got {actual_hash}")

        return len(issues) == 0, issues
