"""
Configuration conflict and discrepancy detection for Linux Server Audit.
"""

from __future__ import annotations
from typing import Any, Dict, List


def detect_conflicts(audit_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detects contradictory configuration fragments and system conflicts."""
    conflicts: List[Dict[str, Any]] = []

    # 1. SSH Configuration Conflicts (Multiple files vs Effective)
    ssh_data = audit_data.get("ssh", {})
    if isinstance(ssh_data, dict):
        config_files = ssh_data.get("config_files", [])
        if len(config_files) > 1:
            conflicts.append({
                "component": "SSH",
                "severity": "NOTICE",
                "title": "Multiple SSH Configuration Fragments",
                "details": f"Found {len(config_files)} SSH config files; effective settings governed by first matching rule in sshd -T",
                "files": config_files,
            })

    # 2. DNS Search Domain / Multiple Resolver Conflicts
    dns_data = audit_data.get("dns", {})
    if isinstance(dns_data, dict):
        nameservers = dns_data.get("nameservers", [])
        if len(nameservers) > 3:
            conflicts.append({
                "component": "DNS",
                "severity": "NOTICE",
                "title": "Excessive Nameservers Configured",
                "details": f"{len(nameservers)} nameservers listed in /etc/resolv.conf; standard glibc resolvers only query the first 3",
            })

    # 3. fstab warnings
    fstab_data = audit_data.get("fstab", {})
    if isinstance(fstab_data, dict):
        for warning in fstab_data.get("warnings", []):
            conflicts.append({
                "component": "fstab",
                "severity": "WARNING",
                "title": "fstab Configuration Issue",
                "details": warning,
            })

    return conflicts
