"""
Deterministic system and hardware health assessment for Linux Server Audit.
"""

from __future__ import annotations
from typing import Any, Dict, List


def evaluate_health(audit_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluates deterministic health checks based purely on collected evidence."""
    findings: List[Dict[str, Any]] = []

    # 1. SMART Disk Health
    smart_data = audit_data.get("smart", {})
    if isinstance(smart_data, dict):
        for dev in smart_data.get("devices", []):
            dev_name = dev.get("device", "Unknown")
            if not dev.get("healthy", True) or dev.get("status") == "FAILED":
                findings.append({
                    "subsystem": "Storage",
                    "severity": "CRITICAL",
                    "title": f"Disk SMART Failure on {dev_name}",
                    "details": f"Physical disk reported unhealthy status: {dev.get('status')}",
                })
            if dev.get("reallocated_sectors", 0) > 0:
                findings.append({
                    "subsystem": "Storage",
                    "severity": "WARNING",
                    "title": f"Reallocated Sectors on {dev_name}",
                    "details": f"{dev.get('reallocated_sectors')} reallocated sectors detected",
                })
            if dev.get("critical_warning", 0) and dev.get("critical_warning", 0) > 0:
                findings.append({
                    "subsystem": "Storage",
                    "severity": "CRITICAL",
                    "title": f"NVMe Critical Warning on {dev_name}",
                    "details": f"NVMe controller flagged critical warning state: {dev.get('critical_warning')}",
                })

    # 2. Filesystem Disk Capacity
    fs_data = audit_data.get("filesystems", {})
    if isinstance(fs_data, dict):
        for mount in fs_data.get("mounts", []):
            pct = mount.get("percent_used", 0)
            target = mount.get("target")
            if pct >= 95:
                findings.append({
                    "subsystem": "Filesystems",
                    "severity": "CRITICAL",
                    "title": f"Disk Space Critical on {target}",
                    "details": f"Mount {target} is {pct}% full ({mount.get('available_formatted')} available)",
                })
            elif pct >= 85:
                findings.append({
                    "subsystem": "Filesystems",
                    "severity": "WARNING",
                    "title": f"Disk Space Warning on {target}",
                    "details": f"Mount {target} is {pct}% full ({mount.get('available_formatted')} available)",
                })

    # 3. Failed systemd units
    sd_data = audit_data.get("systemd", {})
    if isinstance(sd_data, dict):
        for failed in sd_data.get("failed_units", []):
            findings.append({
                "subsystem": "Services",
                "severity": "WARNING",
                "title": f"Failed systemd unit: {failed.get('unit')}",
                "details": f"Active: {failed.get('active')} ({failed.get('sub')}) - {failed.get('description')}",
            })

    # 4. Software RAID degraded state
    raid_data = audit_data.get("raid", {})
    if isinstance(raid_data, dict):
        for deg in raid_data.get("degraded_arrays", []):
            findings.append({
                "subsystem": "Storage",
                "severity": "CRITICAL",
                "title": f"Degraded RAID Array: {deg.get('name')}",
                "details": f"Array {deg.get('device')} ({deg.get('level')}) is operating in degraded state",
            })

    # 5. Pending reboot
    pkg_data = audit_data.get("packages", {})
    if isinstance(pkg_data, dict) and pkg_data.get("reboot_required"):
        findings.append({
            "subsystem": "System",
            "severity": "NOTICE",
            "title": "System Reboot Required",
            "details": "A kernel or package update requires a system reboot to take full effect",
        })

    # 6. OOM killer events
    rh_data = audit_data.get("runtime_health", {})
    if isinstance(rh_data, dict) and rh_data.get("oom_events_count", 0) > 0:
        findings.append({
            "subsystem": "Runtime",
            "severity": "WARNING",
            "title": f"OOM Killer Triggered ({rh_data.get('oom_events_count')} events)",
            "details": "Out of Memory killer recently terminated processes",
        })

    # 7. Expired TLS Certificates
    tls_data = audit_data.get("tls", {})
    if isinstance(tls_data, dict):
        for cert in tls_data.get("expired_certificates", []):
            findings.append({
                "subsystem": "TLS/PKI",
                "severity": "CRITICAL",
                "title": f"Expired TLS Certificate: {cert.get('subject')}",
                "details": f"Certificate expired on {cert.get('not_after')}",
            })
        for cert in tls_data.get("expiring_soon", []):
            findings.append({
                "subsystem": "TLS/PKI",
                "severity": "WARNING",
                "title": f"TLS Certificate Expiring Soon ({cert.get('days_remaining')} days)",
                "details": f"Certificate for {cert.get('subject')} expires on {cert.get('not_after')}",
            })

    return findings
