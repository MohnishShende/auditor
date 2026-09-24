"""
Audit execution engine and CLI orchestrator for Linux Server Audit.
"""

from __future__ import annotations
import argparse
import datetime
import getpass
from pathlib import Path
import platform
import time
from typing import Any, Dict, List, Optional
import yaml

from .. import __version__, __schema_version__
from ..collectors import get_all_collectors
from ..core.collector import CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from ..core.privileges import PrivilegeManager
from ..core.sanitizer import Sanitizer, SanitizerConfig, SanitizationProfile
from ..core.manifest import ManifestGenerator
from ..core.snapshot import SnapshotManager
from ..core.normalizer import Normalizer
from ..topology import (
    TopologyGraph,
    build_storage_topology,
    build_network_topology,
    build_service_topology,
)
from ..analysis import evaluate_health, evaluate_exposure, detect_conflicts
from ..renderers import MarkdownRenderer, JsonRenderer, HtmlRenderer, PdfRenderer


class AuditOrchestrator:
    """Coordinates collector execution, sanitization, analysis, topology, and rendering."""

    def __init__(
        self,
        profile: str = "private",
        output_dir: str = "audits",
        formats: Optional[List[str]] = None,
        config_file: Optional[str] = None,
        quiet: bool = False,
    ) -> None:
        self.profile = profile
        self.output_dir = Path(output_dir)
        self.formats = formats or ["markdown", "json", "html"]
        self.quiet = quiet
        self.privileges = PrivilegeManager()
        self.executor = CommandExecutor(self.privileges)
        self.sanitizer = Sanitizer(SanitizerConfig.from_profile(self.profile))
        self.snapshot_manager = SnapshotManager(self.output_dir)

    def log(self, message: str) -> None:
        if not self.quiet:
            try:
                print(message)
            except UnicodeEncodeError:
                # Fallback to ascii/safe replacement if terminal encoding is restricted
                print(message.encode("ascii", errors="replace").decode("ascii"))

    def run_audit(self) -> Path:
        """Executes full audit pipeline and persists the snapshot bundle."""
        start_time = time.time()
        now_dt = datetime.datetime.now(datetime.timezone.utc).astimezone()
        timestamp_str = Normalizer.iso_timestamp(now_dt)

        self.log("======================================================================")
        self.log(f" Linux Server Audit v{__version__}")
        self.log("======================================================================")
        self.log(f"Profile:       {self.profile.upper()}")
        self.log(f"Timestamp:     {timestamp_str}")
        self.log(f"Sudo Access:   {'Available (Active)' if self.privileges.can_elevate else 'Restricted (Non-root)'}")
        self.log(f"Safety Mode:   STRICT (Zero State Modification)")
        self.log("----------------------------------------------------------------------")
        self.log("Collecting server state...")

        # 1. Discover and instantiate collectors
        all_collectors = get_all_collectors()
        collector_results: Dict[str, CollectorResult] = {}
        collected_data: Dict[str, Any] = {}

        # Shared execution context
        context: Dict[str, Any] = {}

        # 2. Run collectors
        total_collectors = len(all_collectors)
        for idx, (name, collector) in enumerate(all_collectors.items(), start=1):
            if collector.requires_root and not self.privileges.can_elevate:
                res = CollectorResult(
                    collector=name,
                    status=CollectorStatus.PERMISSION_DENIED,
                    message="Elevated privilege required but unavailable",
                )
            else:
                res = collector.run(self.executor, context=context)

            collector_results[name] = res
            collected_data[name] = res.data
            context[name] = res.data

            status_symbol = "✓" if res.status == CollectorStatus.SUCCESS else ("!" if res.status == CollectorStatus.PARTIAL else "•")
            self.log(f"[{status_symbol}] ({idx:02d}/{total_collectors:02d}) {name:<18} [{res.status.value}] ({res.duration_seconds:.2f}s)")

        self.log("----------------------------------------------------------------------")
        self.log("Building topology and analyzing state...")

        # 3. Build Topology
        graph = TopologyGraph()
        storage_chains = build_storage_topology(
            storage_data=collected_data.get("storage", {}),
            lvm_data=collected_data.get("lvm", {}),
            encryption_data=collected_data.get("encryption", {}),
            filesystems_data=collected_data.get("filesystems", {}),
            docker_data=collected_data.get("docker", {}),
            apps_data=collected_data.get("applications", {}),
            graph=graph,
        )
        build_network_topology(
            network_data=collected_data.get("network", {}),
            docker_data=collected_data.get("docker", {}),
            graph=graph,
        )
        service_routes = build_service_topology(
            caddy_data=collected_data.get("caddy", {}),
            ports_data=collected_data.get("ports", {}),
            docker_data=collected_data.get("docker", {}),
            apps_data=collected_data.get("applications", {}),
            graph=graph,
        )

        topology_dict = graph.to_dict()
        topology_dict["storage_chains"] = storage_chains
        topology_dict["service_routes"] = service_routes

        # 4. Deterministic Analysis
        health_findings = evaluate_health(collected_data)
        exposure_findings = evaluate_exposure(collected_data)
        conflicts_findings = detect_conflicts(collected_data)

        analysis_dict = {
            "health": health_findings,
            "exposure": exposure_findings,
            "conflicts": conflicts_findings,
        }

        # 5. Build Canonical Model
        total_duration = time.time() - start_time
        hostname = platform.node()

        metadata = {
            "tool_name": "serveraudit",
            "tool_version": __version__,
            "timestamp": timestamp_str,
            "hostname": hostname,
            "profile": self.profile,
            "duration_seconds": round(total_duration, 4),
            "privileges_available": self.privileges.can_elevate,
            "operating_user": getpass.getuser(),
        }

        canonical_data = {
            "schema_version": __schema_version__,
            "metadata": metadata,
            "system": collected_data.get("system", {}),
            "hardware": collected_data.get("hardware", {}),
            "firmware": collected_data.get("firmware", {}),
            "cpu": collected_data.get("cpu", {}),
            "memory": collected_data.get("memory", {}),
            "pci": collected_data.get("pci", {}),
            "usb": collected_data.get("usb", {}),
            "storage": collected_data.get("storage", {}),
            "smart": collected_data.get("smart", {}),
            "filesystems": collected_data.get("filesystems", {}),
            "fstab": collected_data.get("fstab", {}),
            "lvm": collected_data.get("lvm", {}),
            "raid": collected_data.get("raid", {}),
            "zfs": collected_data.get("zfs", {}),
            "btrfs": collected_data.get("btrfs", {}),
            "encryption": collected_data.get("encryption", {}),
            "network": collected_data.get("network", {}),
            "routes": collected_data.get("routes", {}),
            "dns": collected_data.get("dns", {}),
            "ports": collected_data.get("ports", {}),
            "active_net": collected_data.get("active_net", {}),
            "firewall": collected_data.get("firewall", {}),
            "fail2ban": collected_data.get("fail2ban", {}),
            "ssh": collected_data.get("ssh", {}),
            "users": collected_data.get("users", {}),
            "security": collected_data.get("security", {}),
            "permissions": collected_data.get("permissions", {}),
            "systemd": collected_data.get("systemd", {}),
            "processes": collected_data.get("processes", {}),
            "runtime_health": collected_data.get("runtime_health", {}),
            "packages": collected_data.get("packages", {}),
            "docker": collected_data.get("docker", {}),
            "caddy": collected_data.get("caddy", {}),
            "tls": collected_data.get("tls", {}),
            "applications": collected_data.get("applications", {}),
            "scheduled": collected_data.get("scheduled", {}),
            "backups": collected_data.get("backups", {}),
            "logs": collected_data.get("logs", {}),
            "thermal": collected_data.get("thermal", {}),
            "power": collected_data.get("power", {}),
            "boot": collected_data.get("boot", {}),
            "time": collected_data.get("time", {}),
            "sharing": collected_data.get("sharing", {}),
            "collectors": {name: res.to_dict() for name, res in collector_results.items()},
            "topology": topology_dict,
            "analysis": analysis_dict,
        }

        # 6. Apply Sanitization
        self.log(f"Applying typed sanitization ({self.profile} profile)...")
        sanitized_data = self.sanitizer.sanitize(canonical_data)

        # 7. Render formats
        self.log("Rendering report artifacts...")
        audit_md = MarkdownRenderer.render(sanitized_data)
        audit_html = HtmlRenderer.render(sanitized_data) if "html" in self.formats else None
        audit_pdf = PdfRenderer.render(sanitized_data) if "pdf" in self.formats and PdfRenderer.is_available() else None

        # 8. Manifest & Integrity
        manifest = ManifestGenerator.generate(
            hostname=hostname,
            profile=self.profile,
            duration_seconds=total_duration,
            results=collector_results,
            privileges_available=self.privileges.can_elevate,
            extra_metadata={"timestamp": timestamp_str},
        )

        # 9. Save bundle
        snapshot_dir = self.snapshot_manager.create_snapshot_dir(hostname, timestamp_str)
        checksums = self.snapshot_manager.save_bundle(
            snapshot_dir=snapshot_dir,
            audit_json=sanitized_data,
            audit_md=audit_md,
            manifest_json=manifest,
            audit_html=audit_html,
            audit_pdf_bytes=audit_pdf,
        )

        self.log("======================================================================")
        self.log(f"✓ Audit Complete in {total_duration:.2f} seconds!")
        self.log(f"Output Directory: {snapshot_dir}")
        self.log(f"  ├── audit.md          ({len(audit_md.splitlines())} lines)")
        self.log(f"  ├── audit.json        (Canonical Model)")
        self.log(f"  ├── manifest.json     (Provenance & Manifest)")
        self.log(f"  ├── checksums.sha256  (Cryptographic Verification)")
        if audit_html:
            self.log(f"  └── audit.html        (Standalone Interactive Dashboard)")
        if audit_pdf:
            self.log(f"  └── audit.pdf         (Archival PDF)")
        self.log("======================================================================")

        return snapshot_dir
